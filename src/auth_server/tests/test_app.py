import base64
import json
import re
from collections.abc import Mapping
from datetime import timedelta
from os import environ
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Self
from unittest import IsolatedAsyncioTestCase, TestCase, mock
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import httpx
import yaml
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import base64url_encode
from starlette.testclient import TestClient
from starlette.types import Message

from auth_server.api import init_auth_server_api
from auth_server.cert_utils import (
    cert_within_validity_period,
    rfc8705_fingerprint,
    serialize_certificate,
    wrong_rfc8705_fingerprint,
)
from auth_server.config import ClientKey, load_config
from auth_server.db.transaction_state import AuthSource, FlowState, TransactionState
from auth_server.middleware import JOSEPreparer
from auth_server.models.gnap import (
    AccessTokenFlags,
    AccessTokenRequest,
    Client,
    ContinueRequest,
    FinishInteraction,
    FinishInteractionMethod,
    GrantRequest,
    HashMethod,
    InteractionRequest,
    Key,
    Proof,
    ProofMethod,
    StartInteractionMethod,
)
from auth_server.models.jose import (
    ECJWK,
    SupportedAlgorithms,
    SupportedHTTPMethods,
    SupportedJWSType,
    SupportedJWSTypeLegacy,
)
from auth_server.models.status import Status
from auth_server.saml2 import AuthnInfo, NameID, SAMLAttributes, SessionInfo
from auth_server.testing import MongoTemporaryInstance
from auth_server.tests.utils import create_cert, create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import get_tls_fed_metadata
from auth_server.utils import get_hash_by_name, get_interaction_hash, get_signing_key, hash_with, load_jwks

__author__ = "lundberg"


class MockResponse:
    def __init__(self: Self, content: bytes = b"", status_code: int = 200) -> None:
        self._content = content
        self._status_code = status_code
        self.accessed_status = 0

    @property
    def content(self: Self) -> bytes:
        return self._content

    @property
    def status(self: Self) -> int:
        self.accessed_status += 1
        return self._status_code

    async def text(self: Self) -> str:
        return self._content.decode("utf-8")


class TestAuthServer(TestCase):
    def setUp(self: Self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.config: dict[str, Any] = {
            "testing": "true",
            "log_level": "DEBUG",
            "keystore_path": f"{self.datadir}/testing_jwks.json",
            "signing_key_id": "test-kid",
            "mdq_server": "http://localhost/mdq",
            "auth_token_issuer": "http://testserver",
            "auth_token_audience": "some_audience",
            "auth_flows": json.dumps(["TestFlow"]),
            "mongo_uri": self.mongo_db.uri,
            "logging_config": json.dumps(
                {
                    "loggers": {
                        "saml2": {"level": "WARNING"},
                        "xmlsec": {"level": "INFO"},
                        "urllib3": {"level": "INFO"},
                        "pymongo.serverSelection": {"level": "INFO"},
                        "pymongo.command": {"level": "INFO"},
                        "pymongo.connection": {"level": "INFO"},
                    }
                }
            ),
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        self.transaction_states = self.mongo_db.conn["auth_server"]["transaction_states"]

        with open(f"{self.datadir}/test.cert", "rb") as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        self.client_cert_str = serialize_certificate(cert=self.client_cert)
        with open(f"{self.datadir}/test_mdq.xml", "rb") as f:
            self.mdq_response = f.read()
        self.client_jwk = jwk.JWK.generate(kid="default", kty="EC", crv="P-256")

    def _update_app_config(self: Self, config: dict | None = None) -> None:
        if config is not None:
            environ.clear()
            environ.update(config)
        self._clear_lru_cache()
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    @staticmethod
    def _clear_lru_cache() -> None:
        # Clear lru_cache to allow config update
        load_config.cache_clear()
        load_jwks.cache_clear()
        get_signing_key.cache_clear()
        get_tls_fed_metadata.cache_clear()

    def tearDown(self: Self) -> None:
        self.app = None  # type: ignore
        self.client = None  # type: ignore
        self._clear_lru_cache()
        # clear transaction state db
        self.transaction_states.drop()
        # Clear environment variables
        environ.clear()

    def _get_access_token_claims(self: Self, access_token: dict, client: TestClient | None) -> dict[str, Any]:
        if client is None:
            client = self.client
        response = client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwk.JWK(**response.json()), jwt=access_token["value"])
        assert json.loads(token.header)["kid"] == response.json()["kid"]
        return json.loads(token.claims)

    def _get_transaction_state_by_id(self: Self, transaction_id: str) -> TransactionState:
        doc = self.transaction_states.find_one({"transaction_id": transaction_id})
        assert doc is not None  # please mypy
        assert isinstance(doc, Mapping) is True  # please mypy
        return TransactionState(**doc)

    def _save_transaction_state(self: Self, transaction_state: TransactionState) -> None:
        self.transaction_states.replace_one(
            {"transaction_id": transaction_state.transaction_id}, transaction_state.dict(exclude_none=True)
        )

    def _fake_saml_authentication(self: Self, transaction_id: str) -> None:
        transaction_state = self._get_transaction_state_by_id(transaction_id)
        # seems like mypy no longer understands allow_population_by_field_name
        attributes = SAMLAttributes(
            eppn="test@example.com",
            unique_id="test@example.com",
            targeted_id="idp!sp!unique",
            assurance=[
                "http://www.swamid.se/policy/assurance/al1",
                "http://www.swamid.se/policy/assurance/al2",
                "https://refeds.org/assurance",
                "https://refeds.org/assurance/ID/unique",
                "https://refeds.org/assurance/ID/eppn-unique-no-reassign",
                "https://refeds.org/assurance/IAP/low",
                "https://refeds.org/assurance/IAP/medium",
            ],
            entitlement=["some-entitlement"],
        )
        name_id = NameID(
            format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            sp_name_qualifier="http://test.localhost/saml2-metadata",
            id="some_id",
            name_qualifier="some_name_qualifer",
            sp_provided_id="some_other_id",
        )
        authn_info = [
            AuthnInfo(authn_class="https://refeds.org/profile/mfa", authn_authority=[], authn_instant=utc_now())
        ]
        transaction_state.saml_session_info = SessionInfo(
            issuer="https://idp.example.com",
            attributes=attributes,
            name_id=name_id,
            authn_info=authn_info,
        )
        self._save_transaction_state(transaction_state)

    @staticmethod
    def _get_csrf_token(consent_page: str) -> str:
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', consent_page)
        assert match is not None, "no csrf token found in the consent page"
        return match.group(1)

    def _do_consent(
        self: Self, transaction_id: str, decision: str = "approve", follow_redirects: bool = False
    ) -> httpx.Response:
        """load the consent screen and answer it the way a user would"""
        response = self.client.get(f"/interaction/redirect/{transaction_id}")
        assert response.status_code == 200
        return self.client.post(
            f"/interaction/consent/{transaction_id}",
            data={"csrf_token": self._get_csrf_token(response.text), "decision": decision},
            follow_redirects=follow_redirects,
        )

    def test_get_status_healty(self: Self) -> None:
        response = self.client.get("/status/healthy")
        assert response.status_code == 200
        assert "status" in response.json()
        assert response.json()["status"] == Status.OK.value

    def test_read_jwks(self: Self) -> None:
        response = self.client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert "keys" in response.json()
        keys = response.json()["keys"]
        assert 1 == len(keys)
        assert ECJWK(**keys[0]).dict(exclude_none=True) == keys[0]

    def test_read_jwk(self: Self) -> None:
        response = self.client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        jwk = ECJWK(**response.json())
        assert jwk.dict(exclude_none=True) == response.json()
        assert jwk.kty == "EC"
        assert jwk.kid == "test-kid"
        assert jwk.crv == "P-256"
        assert jwk.x == "RQ4UriZV8y1g97KSZEDzrEAHeN0K0yvfiNjyNjBsqo8"
        assert jwk.y == "eRmcA40T-NIFxostV1E7-GDsavCZ3PVAmzDou-uIpvo"

    def test_read_pem(self: Self) -> None:
        response = self.client.get("/.well-known/public.pem")
        assert response.status_code == 200

    def test_transaction_test_mode(self: Self) -> None:
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.TEST))),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST
        assert claims["aud"] == "some_audience"

    def test_transaction_without_bearer_flag_denied(self: Self) -> None:
        # we can not issue key-bound tokens, so a request without the bearer flag must be denied
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.TEST))),
            access_token=[AccessTokenRequest()],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_request"

    def test_grant_response_cache_control(self: Self) -> None:
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.TEST))),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"

    def test_config_from_yaml(self: Self) -> None:
        # Set absolute path to testing_jwks.json
        config_file_path = f"{self.datadir}/test_config.yaml"
        with open(config_file_path) as f:
            config = yaml.safe_load(f)
        with NamedTemporaryFile(mode="w") as tf:
            config["auth_server"]["keystore_path"] = f"{self.datadir}/testing_jwks.json"
            yaml.dump(config, tf)

            environ["config_file"] = f"{tf.name}"
            environ["config_ns"] = "auth_server"
            self._update_app_config()

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.TEST))),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST
        assert claims["aud"] == "another_audience"
        assert claims["iss"] == "authserver.local"

    def test_transaction_mtls(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.MTLS), cert=self.client_cert_str)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST

    def test_transaction_mtls_new_and_old_fingerprint(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self._update_app_config(config=self.config)

        old_fingerprint = wrong_rfc8705_fingerprint(self.client_cert)
        new_fingerprint = rfc8705_fingerprint(self.client_cert)

        for fingerprint in [old_fingerprint, new_fingerprint]:
            req = GrantRequest(
                client=Client(key=Key(proof=Proof(method=ProofMethod.MTLS), cert_S256=fingerprint)),
                access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            )
            client_header = {"Client-Cert": self.client_cert_str}
            response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
            assert response.status_code == 200
            assert "access_token" in response.json()

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_transaction_mtls_mdq_with_key_reference(self: Self, mock_mdq: AsyncMock) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow", "MDQFlow"])
        self._update_app_config(config=self.config)

        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key="test.localhost"),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.MDQ

    def test_transaction_jws(self: Self) -> None:
        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWS), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        jws_header = {
            "typ": SupportedJWSType.JWS,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        client_header = {"Content-Type": "application/jose"}
        response = self.client.post("/transaction", content=data, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST

    def test_transaction_jws_legacy_typ(self: Self) -> None:
        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWS), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        jws_header = {
            "typ": SupportedJWSTypeLegacy.JWS,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        client_header = {"Content-Type": "application/jose"}
        response = self.client.post("/transaction", content=data, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST

    def test_deserialize_bad_jws(self: Self) -> None:
        client_header = {"Content-Type": "application/jose"}
        response = self.client.post("/transaction", content=b"bogus_jws", headers=client_header)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_client"
        assert response.json()["error"]["description"] == "JWS could not be deserialized"
        assert response.headers["cache-control"] == "no-store"

    def test_transaction_jwsd(self: Self) -> None:
        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWSD), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        jws_header = {
            "typ": SupportedJWSType.JWSD,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }

        payload = req.model_dump_json(exclude_unset=True)

        # create a hash of payload to send in payload place
        payload_digest = hash_with(SHA256(), payload.encode())
        payload_hash = base64url_encode(payload_digest)

        # create detached jws
        _jws = jws.JWS(payload=payload)
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        # Remove payload from serialized jws
        header, _, signature = data.split(".")
        client_header = {"Content-Type": "application/json", "Detached-JWS": f"{header}.{payload_hash}.{signature}"}

        response = self.client.post(
            "/transaction", content=req.model_dump_json(exclude_unset=True), headers=client_header
        )

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST

    def test_transaction_jwsd_legacy_typ(self: Self) -> None:
        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWSD), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        jws_header = {
            "typ": SupportedJWSTypeLegacy.JWSD,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }

        payload = req.model_dump_json(exclude_unset=True)

        # create a hash of payload to send in payload place
        payload_digest = hash_with(SHA256(), payload.encode())
        payload_hash = base64url_encode(payload_digest)

        # create detached jws
        _jws = jws.JWS(payload=payload)
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        # Remove payload from serialized jws
        header, _, signature = data.split(".")
        client_header = {"Content-Type": "application/json", "Detached-JWS": f"{header}.{payload_hash}.{signature}"}

        response = self.client.post(
            "/transaction", content=req.model_dump_json(exclude_unset=True), headers=client_header
        )

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_mdq_flow(self: Self, mock_mdq: AsyncMock) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow", "MDQFlow"])
        self._update_app_config(config=self.config)

        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key="test.localhost"),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.MDQ
        assert claims["entity_id"] == "https://test.localhost"
        assert claims["scopes"] == ["localhost"]
        assert claims["source"] == "http://www.swamid.se/"

    def _setup_remote_tls_fed_test(
        self: Self, entity_id: str, scopes: list[str] | None = None, client_certs: list[str] | None = None
    ) -> bytes:
        if scopes is None:
            scopes = ["test.localhost"]
        if client_certs is None:
            client_certs = [self.client_cert_str]

        self.config["auth_flows"] = json.dumps(["TestFlow", "TLSFEDFlow"])
        self.config["tls_fed_metadata"] = json.dumps(
            [{"remote": "https://metadata.example.com/metadata.jws", "jwks": f"{self.datadir}/tls_fed_jwks.json"}]
        )
        self._update_app_config(config=self.config)

        # Create metadata jws and set it as mock response
        with open(f"{self.datadir}/tls_fed_jwks.json") as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        metadata = create_tls_fed_metadata(
            entity_id=entity_id,
            scopes=scopes,
            client_certs=client_certs,
            issuer="metadata.example.com",
            expires=timedelta(days=14),
        )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key("metadata_signing_key_id"),
            issuer="metadata.example.com",
            expires=timedelta(days=14),
            alg=SupportedAlgorithms.ES256,
        )
        return metadata_jws

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_tls_fed_flow_remote_metadata(self: Self, mock_metadata: AsyncMock) -> None:
        entity_id = "https://test.localhost"
        metadata_jws = self._setup_remote_tls_fed_test(entity_id=entity_id)
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TLSFED
        assert claims["entity_id"] == "https://test.localhost"
        assert claims["scopes"] == ["test.localhost"]
        assert claims["organization_id"] == "SE0123456789"
        assert claims["source"] == "metadata.example.com"

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_tls_fed_flow_remote_metadata_multi_certs(self: Self, mock_metadata: AsyncMock) -> None:
        entity_id = "https://test.localhost"
        new_client_key, new_client_cert = create_cert(common_name="test.localhost")
        new_client_cert_str = serialize_certificate(cert=new_client_cert)
        client_certs = [new_client_cert_str, self.client_cert_str]
        metadata_jws = self._setup_remote_tls_fed_test(entity_id=entity_id, client_certs=client_certs)
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": new_client_cert_str}
        response = self.client.post("/transaction", json=req.model_dump(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TLSFED
        assert claims["entity_id"] == "https://test.localhost"
        assert claims["scopes"] == ["test.localhost"]
        assert claims["organization_id"] == "SE0123456789"
        assert claims["source"] == "metadata.example.com"

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_tls_fed_flow_remote_metadata_expired_client_cert(self: Self, mock_metadata: AsyncMock) -> None:
        # the metadata is what this flow trusts, so certificate validity is not enforced here
        entity_id = "https://test.localhost"
        _, expired_client_cert = create_cert(
            common_name="test.localhost", days_valid=1, valid_from=utc_now() - timedelta(days=2)
        )
        assert cert_within_validity_period(cert=expired_client_cert) is False
        expired_client_cert_str = serialize_certificate(cert=expired_client_cert)
        metadata_jws = self._setup_remote_tls_fed_test(entity_id=entity_id, client_certs=[expired_client_cert_str])
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": expired_client_cert_str}
        response = self.client.post("/transaction", json=req.model_dump(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert access_token["value"] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TLSFED
        assert claims["entity_id"] == entity_id

    def test_tls_fed_flow_local_metadata(self: Self) -> None:
        # Create metadata jws and save it as a temporary file
        with open(f"{self.datadir}/tls_fed_jwks.json") as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = "https://test.localhost"
        metadata = create_tls_fed_metadata(
            entity_id=entity_id,
            scopes=["test.localhost"],
            client_certs=[self.client_cert_str],
            issuer="metadata.example.com",
            expires=timedelta(days=14),
        )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key("metadata_signing_key_id"),
            issuer="metadata.example.com",
            expires=timedelta(days=14),
            alg=SupportedAlgorithms.ES256,
            compact=False,
        )

        with NamedTemporaryFile() as f:
            f.write(metadata_jws)
            f.flush()
            self.config["auth_flows"] = json.dumps(["TestFlow", "TLSFEDFlow"])
            self.config["tls_fed_metadata"] = json.dumps(
                [{"local": f"{f.name}", "jwks": f"{self.datadir}/tls_fed_jwks.json"}]
            )
            self._update_app_config(config=self.config)

            # Start transaction
            req = GrantRequest(
                client=Client(key=entity_id),
                access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            )
            client_header = {"Client-Cert": self.client_cert_str}
            response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
            assert response.status_code == 200
            assert "access_token" in response.json()
            access_token = response.json()["access_token"]
            assert AccessTokenFlags.BEARER.value in access_token["flags"]
            assert access_token["value"] is not None

            # Verify token and check claims
            claims = self._get_access_token_claims(access_token=access_token, client=self.client)
            assert claims["auth_source"] == AuthSource.TLSFED
            assert claims["entity_id"] == "https://test.localhost"
            assert claims["scopes"] == ["test.localhost"]
            assert claims["organization_id"] == "SE0123456789"
            assert claims["source"] == "metadata.example.com"

    @mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock)
    def test_tls_fed_flow_expired_entity(self: Self, mock_metadata: AsyncMock) -> None:
        self.config["auth_flows"] = json.dumps(["TLSFEDFlow"])
        self.config["tls_fed_metadata"] = json.dumps(
            [{"remote": "https://metadata.example.com/metadata.jws", "jwks": f"{self.datadir}/tls_fed_jwks.json"}]
        )
        self._update_app_config(config=self.config)

        # Create metadata jws and set it as mock response
        with open(f"{self.datadir}/tls_fed_jwks.json") as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = "https://test.localhost"
        metadata = create_tls_fed_metadata(
            entity_id=entity_id,
            client_certs=[self.client_cert_str],
            issuer="metadata.example.com",
            expires=timedelta(days=-1),
        )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key("metadata_signing_key_id"),
            issuer="metadata.example.com",
            expires=timedelta(days=-1),
            alg=SupportedAlgorithms.ES256,
        )
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # clear metadata cache
        get_tls_fed_metadata.cache_clear()
        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.model_dump(exclude_none=True), headers=client_header)
        assert response.status_code == 401

    def test_config_flow(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow", "ConfigFlow"])
        del self.config["auth_token_audience"]  # auth_token_audience defaults to None
        client_key = ClientKey(
            proof=Proof(method=ProofMethod.MTLS), cert=self.client_cert_str, claims={"test_claim": "test_claim_value"}
        )
        key_reference = "test_key_ref"
        self.config["client_keys"] = json.dumps({key_reference: client_key.dict(exclude_unset=True)})
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=key_reference),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.CONFIG
        assert claims["sub"] == key_reference
        assert claims["test_claim"] == "test_claim_value"
        assert claims["source"] == "config"
        assert "aud" not in claims

    def test_requested_access_in_jwt(self: Self) -> None:
        grant_request = {
            "access_token": {
                "flags": ["bearer"],
                "access": ["test_access_string", {"type": "test_access", "scope": "a_scope"}],
            },
            "client": {"key": {"proof": "test"}},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]
        assert "access" in access_token
        assert "test_access_string" in access_token["access"]
        for item in access_token["access"]:
            if isinstance(item, dict):
                assert "scope" in item
                assert item["scope"] == "a_scope"

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["aud"] == "some_audience"
        assert "requested_access" in claims
        assert "test_access_string" in claims["requested_access"]
        for item in claims["requested_access"]:
            if isinstance(item, dict):
                assert "scope" in item
                assert item["scope"] == "a_scope"

    def test_transaction_interact_start(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect", "user_code"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # interact response
        assert "interact" in response.json()
        interaction_response = response.json()["interact"]
        assert interaction_response["redirect"].startswith("http://testserver/interaction/redirect/") is True
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]
        transaction_state = self._get_transaction_state_by_id(transaction_id)
        assert interaction_response["user_code"] == transaction_state.user_code

        # continue response
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        continue_reference = continue_response["uri"].split("http://testserver/continue/")[1]
        assert continue_reference == transaction_state.continue_reference
        assert continue_response["access_token"]["bound"] is True
        assert continue_response["access_token"]["value"] == transaction_state.continue_access_token

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

    def test_interaction_requires_consent_after_authentication(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"], "access": ["some_access"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # start the interaction and authenticate
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        self._fake_saml_authentication(transaction_id=transaction_id)

        # returning after authentication must show a consent screen, not finish the interaction
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 200
        assert "<h1>Approve access</h1>" in response.text
        assert "some_access" in response.text

        # authentication alone must not approve the transaction
        assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.PENDING

    def test_interaction_consent_approve(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        self.client.get(interaction_response["redirect"], follow_redirects=False)
        self._fake_saml_authentication(transaction_id=transaction_id)

        response = self._do_consent(transaction_id=transaction_id, decision="approve")
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text
        assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.APPROVED

    def test_interaction_consent_deny(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        continue_response = response.json()["continue"]
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        self.client.get(interaction_response["redirect"], follow_redirects=False)
        self._fake_saml_authentication(transaction_id=transaction_id)

        response = self._do_consent(transaction_id=transaction_id, decision="deny")
        assert response.status_code == 200
        assert "<h1>Access denied</h1>" in response.text
        assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.DENIED

        # the client must be told the user said no instead of being kept polling
        response = self.client.post(
            continue_response["uri"],
            json={},
            headers={"Authorization": f"GNAP {continue_response['access_token']['value']}"},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "user_denied"

    def test_interaction_consent_rejects_wrong_csrf_token(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        self.client.get(interaction_response["redirect"], follow_redirects=False)
        self._fake_saml_authentication(transaction_id=transaction_id)
        # load the consent screen so a csrf token exists to get wrong
        assert self.client.get(interaction_response["redirect"]).status_code == 200

        response = self.client.post(
            f"/interaction/consent/{transaction_id}",
            data={"csrf_token": "not_the_csrf_token", "decision": "approve"},
            follow_redirects=False,
        )
        assert response.status_code == 403
        assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.PENDING

    def test_interaction_consent_rejects_other_browser(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        self.client.get(interaction_response["redirect"], follow_redirects=False)
        self._fake_saml_authentication(transaction_id=transaction_id)
        response = self.client.get(interaction_response["redirect"])
        assert response.status_code == 200
        csrf_token = self._get_csrf_token(response.text)

        # a browser that did not start the interaction must not be able to see or answer the consent screen,
        # even if it knows the transaction id and the csrf token
        other_browser = TestClient(self.app)
        response = other_browser.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 403

        response = other_browser.post(
            f"/interaction/consent/{transaction_id}",
            data={"csrf_token": csrf_token, "decision": "approve"},
            follow_redirects=False,
        )
        assert response.status_code == 403
        assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.PENDING

    def test_interaction_consent_two_transactions_in_one_browser(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }

        transaction_ids = []
        for _ in range(2):
            response = self.client.post("/transaction", json=grant_request)
            assert response.status_code == 200
            redirect_url = response.json()["interact"]["redirect"]
            transaction_id = redirect_url.split("http://testserver/interaction/redirect/")[1]
            transaction_ids.append(transaction_id)
            # start both interactions in the same browser before finishing either of them
            assert self.client.get(redirect_url, follow_redirects=False).status_code == 303
            self._fake_saml_authentication(transaction_id=transaction_id)

        # starting a second interaction must not lock the browser out of the first one
        for transaction_id in transaction_ids:
            response = self._do_consent(transaction_id=transaction_id)
            assert response.status_code == 200
            assert "<h1>Interaction finished</h1>" in response.text
            assert self._get_transaction_state_by_id(transaction_id).flow_state is FlowState.APPROVED

    def test_transaction_interact_redirect_finish(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {
                "start": ["redirect", "user_code"],
                "finish": {"method": "redirect", "uri": "https://example.com/redirect", "nonce": "abc123"},
            },
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"] == "http://testserver/continue"

        assert "interact" in response.json()
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 303

    @mock.patch("aiohttp.ClientSession.post", new_callable=AsyncMock)
    def test_transaction_interact_push_finish(self: Self, mock_response: AsyncMock) -> None:
        mock_response.return_value = MockResponse()  # mock response to background push task
        assert mock_response.return_value.accessed_status == 0

        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {
                "start": ["redirect", "user_code"],
                "finish": {"method": "push", "uri": "https://example.com/push", "nonce": "abc123"},
            },
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"] == "http://testserver/continue"

        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert mock_response.return_value.accessed_status == 1

    def test_transaction_interact_user_code_start(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["user_code"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        interaction_response = response.json()["interact"]

        response = self.client.get("/interaction/code")
        assert response.status_code == 200
        assert '<label for="user-code">Input your code</label>' in response.text

        response = self.client.post(
            "/interaction/code", data={"user_code": interaction_response["user_code"]}, follow_redirects=False
        )
        assert response.status_code == 303

        transaction_id = response.headers["location"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(response.headers["location"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # the user is sent back to the interaction endpoint after a successful SAML authentication
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

    def test_transaction_interact_user_code_uri_start(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["user_code_uri"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        interaction_response = response.json()["interact"]

        response = self.client.get(interaction_response["user_code_uri"]["uri"])
        assert response.status_code == 200
        assert '<label for="user-code">Input your code</label>' in response.text

        response = self.client.post(
            "/interaction/code",
            data={"user_code": interaction_response["user_code_uri"]["code"]},
            follow_redirects=False,
        )
        assert response.status_code == 303

        transaction_id = response.headers["location"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(response.headers["location"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

    def test_transaction_continue(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.TEST
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"
        assert claims["saml_assurance"] is not None
        assert claims["saml_entitlement"] is not None

    def test_transaction_continue_replay_after_finalize(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        continue_response = response.json()["continue"]
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed -> grant finalized
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})
        assert response.status_code == 200
        assert "access_token" in response.json()

        # replay the same continuation request against the now-finalized transaction
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_continuation"

    def test_transaction_continue_check_progress(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do continue request before interaction is done
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})
        # expect the same continue response as the first time
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})

        # TODO: temporary end of test (same as test for test flow)
        #   this tests need to see if we correctly validate proof
        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"

    def test_continue_access_token_rotates_on_poll(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        continue_response = response.json()["continue"]
        first_token = continue_response["access_token"]["value"]

        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]
        expires_at_before_poll = self._get_transaction_state_by_id(transaction_id).expires_at

        # poll before interaction completes -> pending response with a rotated token
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": f"GNAP {first_token}"})
        assert response.status_code == 200
        second_token = response.json()["continue"]["access_token"]["value"]
        assert second_token != first_token

        # polling must not extend the transaction's expiry (finding: unbounded TTL growth)
        expires_at_after_poll = self._get_transaction_state_by_id(transaction_id).expires_at
        assert expires_at_after_poll == expires_at_before_poll

        # the used token must no longer be accepted
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": f"GNAP {first_token}"})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_continuation"

        # the rotated token works
        response = self.client.post(
            continue_response["uri"], json={}, headers={"Authorization": f"GNAP {second_token}"}
        )
        assert response.status_code == 200

    def test_delete_continue_revokes_grant(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        continue_response = response.json()["continue"]
        token = continue_response["access_token"]["value"]

        # revoke the grant
        response = self.client.delete(continue_response["uri"], headers={"Authorization": f"GNAP {token}"})
        assert response.status_code == 204

        # the transaction is gone
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": f"GNAP {token}"})
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "invalid_continuation"

    def test_token_management_revoke(self: Self) -> None:
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.TEST))),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        access_token = response.json()["access_token"]
        assert "manage" in access_token
        manage = access_token["manage"]
        assert manage["uri"].startswith("http://testserver/token/")
        mgmt_token = manage["access_token"]["value"]

        # wrong management token is denied
        response = self.client.delete(manage["uri"], headers={"Authorization": "GNAP wrong"})
        assert response.status_code == 401

        # rotation is not supported
        response = self.client.post(manage["uri"], headers={"Authorization": f"GNAP {mgmt_token}"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_rotation"

        # revoke the token
        response = self.client.delete(manage["uri"], headers={"Authorization": f"GNAP {mgmt_token}"})
        assert response.status_code == 204

        # revoking again finds nothing
        response = self.client.delete(manage["uri"], headers={"Authorization": f"GNAP {mgmt_token}"})
        assert response.status_code == 404

    def test_transaction_interaction_flow_requires_interaction(self: Self) -> None:
        # a grant request without an interaction request must not be approved by the interaction flow,
        # as the flow has no resource owner authentication to base the approval on
        self.config["auth_flows"] = json.dumps(["InteractionFlow"])
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.MTLS), cert=self.client_cert_str)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)

        assert response.status_code == 401
        assert response.json()["error"]["code"] == "request_denied"

    def test_transaction_mtls_continue(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["InteractionFlow"])
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.MTLS), cert=self.client_cert_str)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            interact=InteractionRequest(start=[StartInteractionMethod.REDIRECT]),
        )
        client_header = {"Client-Cert": self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do continue request before interaction is done
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        client_header = {"Client-Cert": self.client_cert_str, "Authorization": authorization_header}
        response = self.client.post(continue_response["uri"], json={}, headers=client_header)
        # expect the same continue response as the first time, but with a rotated continuation access token
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None
        # the continue access token is rotated on every poll, so update the header used for the next request
        client_header["Authorization"] = f"GNAP {continue_response['access_token']['value']}"

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        response = self.client.post(continue_response["uri"], json={}, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.INTERACTION
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"

    def test_transaction_jws_continue(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["InteractionFlow"])
        self._update_app_config(config=self.config)

        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWS), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            interact=InteractionRequest(start=[StartInteractionMethod.REDIRECT]),
        )
        jws_header = {
            "typ": SupportedJWSType.JWS,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        content = _jws.serialize(compact=True)

        client_header = {"Content-Type": "application/jose+json"}
        response = self.client.post("/transaction", content=content, headers=client_header)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        jws_header["uri"] = continue_response["uri"]
        jws_header["created"] = int(utc_now().timestamp())
        # calculate ath header value
        access_token_hash = hash_with(SHA256(), continue_response["access_token"]["value"].encode())
        jws_header["ath"] = base64.urlsafe_b64encode(access_token_hash).decode("ascii").rstrip("=")
        _jws = jws.JWS(payload="{}")
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        continue_data = _jws.serialize(compact=True)
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        client_header["Authorization"] = authorization_header
        response = self.client.post(continue_response["uri"], content=continue_data, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.INTERACTION
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"

    def test_transaction_jws_continue_redirect_finish(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["InteractionFlow"])
        self._update_app_config(config=self.config)

        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)

        client_nonce = "client_nonce"
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWS), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            interact=InteractionRequest(
                start=[StartInteractionMethod.REDIRECT],
                finish=FinishInteraction(
                    method=FinishInteractionMethod.REDIRECT,
                    uri="https://example.com/redirect",
                    nonce=client_nonce,
                ),
            ),
        )
        transaction_url = "http://testserver/transaction"
        jws_header = {
            "typ": SupportedJWSType.JWS,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": transaction_url,
            "created": int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        content = _jws.serialize(compact=True)

        client_header = {"Content-Type": "application/jose+json"}
        response = self.client.post("/transaction", content=content, headers=client_header)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]
        as_nonce = interaction_response["finish"]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 303

        # "receive" redirect back to our endpoint and pick out hash and interact_ref
        urlparsed_redirect_location = urlparse(response.headers["location"])
        qs = parse_qs(urlparsed_redirect_location.query)
        interact_hash = qs["hash"][0]
        interact_ref = qs["interact_ref"][0]

        # verify hash
        hash_alg = get_hash_by_name(hash_name=HashMethod.SHA_256.value)  # defaults to SHA256
        plaintext = f"{client_nonce}\n{as_nonce}\n{interact_ref}\n{transaction_url}".encode(encoding="ascii")
        hash_res = hash_with(hash_alg, plaintext)
        assert base64.urlsafe_b64encode(hash_res).decode(encoding="ascii").rstrip("=") == interact_hash

        # continue request after interaction is completed
        jws_header["uri"] = continue_response["uri"]
        jws_header["created"] = int(utc_now().timestamp())
        # calculate ath header value
        access_token_hash = hash_with(SHA256(), continue_response["access_token"]["value"].encode())
        jws_header["ath"] = base64.urlsafe_b64encode(access_token_hash).decode("ascii").rstrip("=")
        # create jws from continue request
        _jws = jws.JWS(payload=ContinueRequest(interact_ref=interact_ref).json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        continue_data = _jws.serialize(compact=True)
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        client_header["Authorization"] = authorization_header
        response = self.client.post(continue_response["uri"], content=continue_data, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.INTERACTION
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"

    def test_transaction_jwsd_continue(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["InteractionFlow"])
        self._update_app_config(config=self.config)

        client_key_dict = self.client_jwk.export_public(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.JWSD), jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            interact=InteractionRequest(start=[StartInteractionMethod.REDIRECT]),
        )
        jws_header = {
            "typ": SupportedJWSType.JWSD,
            "alg": SupportedAlgorithms.ES256.value,
            "kid": self.client_jwk.key_id,
            "htm": SupportedHTTPMethods.POST.value,
            "uri": "http://testserver/transaction",
            "created": int(utc_now().timestamp()),
        }

        payload = req.model_dump_json(exclude_unset=True)

        # create a hash of payload to send in payload place
        payload_digest = hash_with(SHA256(), payload.encode())
        payload_hash = base64url_encode(payload_digest)

        _jws = jws.JWS(payload=payload)
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        # Remove payload from serialized jws
        header, _, signature = data.split(".")
        client_header = {"Content-Type": "application/json", "Detached-JWS": f"{header}.{payload_hash}.{signature}"}

        response = self.client.post(
            "/transaction", content=req.model_dump_json(exclude_unset=True), headers=client_header
        )
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        jws_header["uri"] = continue_response["uri"]
        jws_header["created"] = int(utc_now().timestamp())
        # calculate ath header value
        access_token_hash = hash_with(SHA256(), continue_response["access_token"]["value"].encode())
        jws_header["ath"] = base64.urlsafe_b64encode(access_token_hash).decode("ascii").rstrip("=")
        # create hash of empty payload to send in payload place
        payload = "{}"
        payload_digest = hash_with(SHA256(), payload.encode())
        payload_hash = base64url_encode(payload_digest)
        _jws = jws.JWS(payload=payload)
        _jws.add_signature(
            key=self.client_jwk,
            protected=json.dumps(jws_header),
        )
        continue_data = _jws.serialize(compact=True)

        # Remove payload from serialized jws
        continue_header, _, continue_signature = continue_data.split(".")
        client_header = {
            "Content-Type": "application/json",
            "Detached-JWS": f"{continue_header}.{payload_hash}.{continue_signature}",
        }

        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        client_header["Authorization"] = authorization_header
        response = self.client.post(continue_response["uri"], content=payload, headers=client_header)

        assert response.status_code == 200
        assert "access_token" in response.json()
        access_token = response.json()["access_token"]
        assert AccessTokenFlags.BEARER.value in access_token["flags"]

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims["auth_source"] == AuthSource.INTERACTION
        assert claims["aud"] == "some_audience"
        assert claims["saml_issuer"] == "https://idp.example.com"
        assert claims["saml_eppn"] == "test@example.com"

    def test_subject_request_response(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {"start": ["redirect"]},
            "subject": {"assertion_formats": ["saml2"]},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200

        # continue response with no continue reference in uri
        assert "continue" in response.json()
        continue_response = response.json()["continue"]
        assert continue_response["uri"].startswith("http://testserver/continue/") is True
        assert continue_response["access_token"]["value"] is not None

        # do interaction
        interaction_response = response.json()["interact"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # check redirect to SAML SP
        response = self.client.get(interaction_response["redirect"], follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/saml2/sp/authn/")

        # fake a completed SAML authentication
        self._fake_saml_authentication(transaction_id=transaction_id)

        # complete interaction
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200
        assert "<h1>Interaction finished</h1>" in response.text

        # continue request after interaction is completed
        authorization_header = f"GNAP {continue_response['access_token']['value']}"
        response = self.client.post(continue_response["uri"], json={}, headers={"Authorization": authorization_header})

        assert response.status_code == 200
        assert "subject" in response.json()
        subject = response.json()["subject"]
        assert subject["assertions"][0]["format"] == "saml2"
        assertion = json.loads(subject["assertions"][0]["value"])
        assert assertion["issuer"] == "https://idp.example.com"
        assert assertion["attributes"]["eduPersonPrincipalName"] == "test@example.com"

    def test_interaction_finish_redirect_uses_303(self: Self) -> None:
        self.config["auth_flows"] = json.dumps(["TestFlow"])
        self.config["pysaml2_config_path"] = str(Path(__file__).with_name("data") / "saml" / "saml2_settings.py")
        self.config["saml2_discovery_service_url"] = "https://disco.example.com/ds/"
        self._update_app_config(config=self.config)

        grant_request = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "test"}},
            "interact": {
                "start": ["redirect"],
                "finish": {"method": "redirect", "uri": "https://client.example.com/callback", "nonce": "abc123"},
            },
        }
        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        interaction_response = response.json()["interact"]
        as_nonce = interaction_response["finish"]
        transaction_id = interaction_response["redirect"].split("http://testserver/interaction/redirect/")[1]

        # fake a completed SAML authentication, then complete the interaction
        self._fake_saml_authentication(transaction_id=transaction_id)
        response = self._do_consent(transaction_id=transaction_id)

        # RFC 9635 requires 303 for the interaction finish redirect
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("https://client.example.com/callback?")

        query = parse_qs(urlparse(location).query)
        transaction_state = self._get_transaction_state_by_id(transaction_id)
        assert transaction_state.interaction_reference is not None
        expected_hash = get_interaction_hash(
            client_nonce="abc123",
            as_nonce=as_nonce,
            interact_ref=transaction_state.interaction_reference,
            transaction_url="http://testserver/transaction",
        )
        assert query["hash"][0] == expected_hash
        assert query["interact_ref"][0] == transaction_state.interaction_reference

    def test_transaction_discovery(self: Self) -> None:
        response = self.client.options("/transaction")
        assert response.status_code == 200
        body = response.json()
        assert body["grant_request_endpoint"] == "http://testserver/transaction"
        assert body["interaction_start_modes_supported"] == ["redirect", "user_code", "user_code_uri"]
        assert body["interaction_finish_methods_supported"] == ["redirect", "push"]
        assert body["key_proofs_supported"] == ["mtls", "jws", "jwsd"]
        assert body["assertion_formats_supported"] == ["saml2"]
        assert body["key_rotation_supported"] is False

    def test_gnap_error_response_format(self: Self) -> None:
        # unauthenticated continuation request must return a GNAP error object
        response = self.client.post("/continue", json={})
        assert response.status_code == 401
        error = response.json()["error"]
        assert error["code"] == "invalid_continuation"
        assert "description" in error
        assert response.headers["cache-control"] == "no-store"


class TestJOSEPreparer(IsolatedAsyncioTestCase):
    """Unit tests for JOSEPreparer._prepare_jose_message that don't go through TestClient.

    TestClient/httpx always deliver the request body as a single ASGI message, so it can't
    exercise the two-message (body + trailing empty message with more_body=True) sequence
    real ASGI servers use. Drive _prepare_jose_message directly with a scripted receive.
    """

    async def test_more_body_cleared_after_trailing_message(self: Self) -> None:
        client_jwk = jwk.JWK.generate(kid="default", kty="EC", crv="P-256")
        _jws = jws.JWS(payload=json.dumps({"hello": "world"}))
        _jws.add_signature(key=client_jwk, protected=json.dumps({"alg": "ES256"}))
        body = _jws.serialize(compact=True).encode("utf-8")

        messages: list[Message] = [
            {"type": "http.request", "body": body, "more_body": True},
            {"type": "http.request", "body": b"", "more_body": False},
        ]

        async def scripted_receive() -> Message:
            return messages.pop(0)

        preparer = JOSEPreparer(app=AsyncMock())
        preparer.receive = scripted_receive
        scope: dict[str, Any] = {"headers": [], "state": {}}

        message = await scripted_receive()
        error_response = await preparer._prepare_jose_message(scope, message)

        assert error_response is None
        # the trailing message was consumed, and the buffered message must no longer
        # advertise more body - the full payload is already in message["body"]
        assert message.get("more_body") is False
        assert message["body"] == json.dumps({"hello": "world"}).encode("utf-8")
        assert messages == []  # trailing message was drained
