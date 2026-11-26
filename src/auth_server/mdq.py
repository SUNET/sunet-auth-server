import logging
import ssl as ssl_module
from collections import OrderedDict
from collections import OrderedDict as _OrderedDict
from enum import StrEnum
from pyexpat import ExpatError
from typing import Any, Self

import aiohttp
import xmltodict
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import Certificate
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

from auth_server.cert_utils import load_pem_from_str, rfc8705_fingerprint, serialize_certificate
from auth_server.config import load_config
from auth_server.models.gnap import Key, Proof, ProofMethod
from auth_server.utils import get_values, hash_with

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class KeyUse(StrEnum):
    SIGNING = "signing"
    ENCRYPTION = "encryption"


class MDQBase(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)


class MDQCert(MDQBase):
    use: KeyUse
    cert: Certificate

    @field_validator("cert", mode="before")
    @classmethod
    def deserialize_cert(cls: type["MDQCert"], v: str) -> Certificate:
        if isinstance(v, Certificate):
            return v
        return load_pem_from_str(v)

    @model_serializer
    def serialize_mdq_cert(self: Self) -> dict[str, Any]:
        """
        serialize Certificate on model_dump
        """
        return {"use": self.use.value, "cert": serialize_certificate(self.cert)}


class MDQData(MDQBase):
    certs: list[MDQCert] = Field(default_factory=list)
    metadata: OrderedDict = Field(default_factory=_OrderedDict)


async def fetch_mdq_xml(entity_id: str, mdq_url: str, ssl: ssl_module.SSLContext | bool | None = None) -> str | None:
    """
    Fetch the raw metadata xml for entity_id from an MDQ server, None if it could not be fetched.

    ssl is passed on to aiohttp as is (an SSLContext as trust anchor, False to skip TLS verification). None keeps the
    aiohttp default, the parameter is then not passed at all.
    """
    timeout = load_config().http_client_timeout
    # SHA1 hash and create hex representation of entity id
    entity_id_hash = hash_with(SHA1(), entity_id.encode())
    identifier = f"{{sha1}}{entity_id_hash.hex()}"
    logger.debug(f"mdq identifier: {identifier}")

    # Get xml from the MDQ service
    headers = {"Accept": "application/samlmetadata+xml"}
    url = f"{mdq_url}/{identifier}"
    logger.debug(f"Trying {url}")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout.total_seconds())) as session:
            extra: dict[str, Any] = {} if ssl is None else {"ssl": ssl}
            response = await session.get(url=url, headers=headers, **extra)
            final_url = str(response.url)
            if url.lower().startswith("https://"):
                # refuse a downgrade anywhere in the redirect chain, also one that comes back to https afterwards
                # (the request over http was already exposed to a network attacker)
                chain = [str(r.url) for r in getattr(response, "history", ())] + [final_url]
                downgraded = next((u for u in chain if u.lower().startswith("http://")), None)
                if downgraded is not None:
                    logger.error(f"{url} redirected to {downgraded}, refusing the https to http downgrade")
                    return None
            if response.status != 200:
                logger.error(f"{url} returned {response.status}")
                return None
            return await response.text()
    except (aiohttp.ClientError, TimeoutError, UnicodeDecodeError) as e:
        logger.exception(f"{url} failed: {e!r}")
        return None


async def xml_mdq_get(entity_id: str, mdq_url: str) -> MDQData:
    xml = await fetch_mdq_xml(entity_id=entity_id, mdq_url=mdq_url)
    if xml is None:
        return MDQData()

    # Parse the xml to a OrderedDict and grab the certs and their use
    try:
        # TODO: Should we use defusedxml.expatbuilder?
        entity = xmltodict.parse(xml, process_namespaces=True)
        certs = []
        # Certs
        for key_descriptor in list(get_values(key="urn:oasis:names:tc:SAML:2.0:metadata:KeyDescriptor", obj=entity))[0]:
            use = list(get_values(key="@use", obj=key_descriptor))[0]
            raw_cert = list(get_values(key="http://www.w3.org/2000/09/xmldsig#:X509Certificate", obj=key_descriptor))[0]
            cert = load_pem_from_str(raw_cert)
            certs.append(MDQCert(use=KeyUse(use), cert=cert))
        return MDQData(certs=certs, metadata=entity)
    except (ExpatError, ValueError):  # TODO: handle exceptions properly
        logger.exception(f"Failed to parse mdq entity: {entity_id}")
    return MDQData()


async def mdq_data_to_keys(mdq_data: MDQData) -> list[Key]:
    keys = list()
    signing_certs = [item.cert for item in mdq_data.certs if item.use == KeyUse.SIGNING]
    for cert in signing_certs:
        _fingerprint = rfc8705_fingerprint(cert)
        logger.info(f"Found cert in metadata, S256: {_fingerprint}")
        keys.append(
            Key(
                proof=Proof(method=ProofMethod.MTLS),
                cert_S256=_fingerprint,
            )
        )
    return keys
