# -*- coding: utf-8 -*-
import base64
import copy
import json
from datetime import timedelta
from pathlib import Path
from typing import Optional, Union
from unittest import IsolatedAsyncioTestCase

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk

from auth_server.models.jose import SupportedAlgorithms
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadata
from auth_server.models.tls_fed_metadata import RegisteredExtensions
from auth_server.tests.utils import create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import Metadata, MetadataEntity, load_metadata, load_metadata_source

__author__ = "lundberg"


class TestTLSMetadata(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.entity_id = "https://test.localhost"
        self.issuer = "metadata.example.com"
        self.about_now = utc_now()
        self.max_age = timedelta(days=365)
        self.expires = timedelta(days=14)
        self.cache_ttl = timedelta(hours=1)
        self.scopes = ["test.localhost"]

        # Create metadata jws and save it as a temporary file
        with open(f"{self.datadir}/tls_fed_jwks.json", "r") as f:
            self.tls_fed_jwks = jwk.JWKSet()
            self.tls_fed_jwks.import_keyset(f.read())

        with open(f"{self.datadir}/test.cert", "rb") as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        self.client_cert_str = base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode("utf-8")

    async def _load_metadata(
        self, metadata: Optional[Union[TLSFEDMetadata, str]] = None, strict: bool = True
    ) -> Optional[Metadata]:
        if metadata is None:
            metadata = create_tls_fed_metadata(
                entity_id=self.entity_id,
                cache_ttl=self.cache_ttl.seconds,
                scopes=self.scopes,
                client_cert=self.client_cert_str,
            )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=self.tls_fed_jwks.get_key("metadata_signing_key_id"),
            issuer=self.issuer,
            issue_time=self.about_now,
            expires=self.expires,
            alg=SupportedAlgorithms.ES256,
            compact=False,
        ).decode("utf-8")

        metadata_source = await load_metadata_source(raw_jws=metadata_jws, jwks=self.tls_fed_jwks, strict=strict)
        if metadata_source is None:
            return None
        return await load_metadata(metadata_sources=[metadata_source], max_age=self.max_age)

    async def test_parse_metadata(self):
        metadata = await self._load_metadata()
        issuer_metadata = list(metadata.issuer_metadata.values())[0]
        assert issuer_metadata is not None
        assert issuer_metadata.renew_at == (self.about_now + self.cache_ttl).replace(microsecond=0)
        assert len(issuer_metadata.entities) == 1
        for entity_id, entity in issuer_metadata.entities.items():
            assert isinstance(entity, MetadataEntity) is True
            assert entity.issuer == self.issuer
            assert entity.entity_id == self.entity_id
            assert entity.expires_at == (self.about_now + self.expires).replace(microsecond=0)
            assert entity.extensions.saml_scope.scope == self.scopes

    async def test_parse_faulty_metadata(self):
        serialized_metadata = create_tls_fed_metadata(
            entity_id=self.entity_id,
            cache_ttl=self.cache_ttl.seconds,
            scopes=self.scopes,
            client_cert=self.client_cert_str,
        ).json(by_alias=True)
        deserialized_metadata = json.loads(serialized_metadata)
        entity = deserialized_metadata["entities"][0]

        # introduce errors in entity data
        bad_extension_entity = copy.deepcopy(entity)

        # bad saml scope extension
        bad_extension_entity["entity_id"] = "https://bad-extension-entity.local"
        saml_scope_extension = bad_extension_entity["extensions"][RegisteredExtensions.SAML_SCOPE.value]
        saml_scope_extension["not_scope"] = saml_scope_extension["scope"]
        del saml_scope_extension["scope"]
        bad_extension_entity["extensions"][RegisteredExtensions.SAML_SCOPE.value] = saml_scope_extension

        deserialized_metadata["entities"].extend([bad_extension_entity])
        modified_metadata = json.dumps(deserialized_metadata)
        # no metadata should be returned when using default strict mode
        metadata = await self._load_metadata(metadata=modified_metadata, strict=True)
        assert metadata is None

        # valid entities should be returned when using non-strict mode
        metadata = await self._load_metadata(metadata=modified_metadata, strict=False)
        for issuer_metadata in metadata.issuer_metadata.values():
            assert issuer_metadata is not None
            assert len(issuer_metadata.entities) == 1

    async def test_parse_unregistered_extension_in_metadata(self):
        serialized_metadata = create_tls_fed_metadata(
            entity_id=self.entity_id,
            cache_ttl=self.cache_ttl.seconds,
            scopes=self.scopes,
            client_cert=self.client_cert_str,
        ).model_dump_json(by_alias=True)
        deserialized_metadata = json.loads(serialized_metadata)

        entity = deserialized_metadata["entities"][0]
        unknown_extension_entity = copy.deepcopy(entity)
        unknown_extension_entity["entity_id"] = "https://unknown_extension_entity"
        unknown_extension_entity["extensions"]["not_a_registered_extension"] = {"some_key": "some_value"}
        deserialized_metadata["entities"].extend([unknown_extension_entity])
        modified_metadata = json.dumps(deserialized_metadata)
        # both entities should be returned when using strict mode
        metadata = await self._load_metadata(metadata=modified_metadata, strict=True)

        issuer_metadata = list(metadata.issuer_metadata.values())[0]
        assert issuer_metadata is not None
        assert len(issuer_metadata.entities) == 2
        # but the unregistered extension should be removed
        entity = issuer_metadata.entities["https://unknown_extension_entity"]
        assert entity.extensions.saml_scope.scope == self.scopes
        assert entity.extensions.model_dump()["not_a_registered_extension"] == {"some_key": "some_value"}
