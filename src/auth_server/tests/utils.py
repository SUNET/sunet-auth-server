# -*- coding: utf-8 -*-

import json
from datetime import datetime, timedelta
from typing import List, Optional, Union

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from jwcrypto import jwk, jws

from auth_server.models.jose import SupportedAlgorithms
from auth_server.models.tls_fed_metadata import CertIssuers, Entity, Extensions
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadata
from auth_server.models.tls_fed_metadata import SAMLScopeExtension
from auth_server.time_utils import utc_now

__author__ = "lundberg"


def tls_fed_metadata_to_jws(
    metadata: Union[TLSFEDMetadata, str],
    key: jwk.JWK,
    issuer: str,
    expires: timedelta,
    alg: SupportedAlgorithms,
    issue_time: Optional[datetime] = None,
    compact: bool = True,
) -> bytes:
    if isinstance(metadata, TLSFEDMetadata):
        payload = metadata.json(exclude_unset=True)
    else:
        payload = metadata

    if issue_time is None:
        issue_time = utc_now()
    expire_time = issue_time + expires
    protected_header = {
        "iss": issuer,
        "iat": int(issue_time.timestamp()),
        "exp": int(expire_time.timestamp()),
        "alg": alg.value,
        "kid": key.key_id,
    }
    _jws = jws.JWS(payload=payload)
    _jws.add_signature(key=key, alg=alg.value, protected=json.dumps(protected_header))
    return _jws.serialize(compact=compact).encode()


def create_tls_fed_metadata(
    entity_id: str,
    client_certs: list[str],
    cache_ttl: int = 3600,
    organization_id: str = "SE0123456789",
    scopes: Optional[List[str]] = None,
) -> TLSFEDMetadata:
    if scopes is None:
        scopes = list()

    entities = [
        Entity(
            entity_id=entity_id,
            organization="Test Org",
            organization_id=organization_id,
            issuers=[CertIssuers(x509certificate=client_cert) for client_cert in client_certs],
            extensions=Extensions(saml_scope=SAMLScopeExtension(scope=scopes)),
        )
    ]
    return TLSFEDMetadata(version="1.0.0", cache_ttl=cache_ttl, entities=entities)


def create_cert(
    common_name: str, alt_names: list[str] | None = None, days_valid: int = 1
) -> tuple[RSAPrivateKey, Certificate]:
    if alt_names is None:
        alt_names = list()
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ""),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    _alt_names = [x509.DNSName(alt_name) for alt_name in alt_names]
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName(_alt_names),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert
