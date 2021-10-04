# -*- coding: utf-8 -*-

import json
from datetime import datetime, timedelta
from typing import List, Optional, Union

from jwcrypto import jwk, jws

from auth_server.models.jose import SupportedAlgorithms
from auth_server.models.tls_fed_metadata import Entity
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadata
from auth_server.models.tls_fed_metadata import RegisteredExtensions
from auth_server.time_utils import utc_now

__author__ = 'lundberg'


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
        'iss': issuer,
        'iat': int(issue_time.timestamp()),
        'exp': int(expire_time.timestamp()),
        'alg': alg.value,
        'kid': key.key_id,
    }
    _jws = jws.JWS(payload=payload)
    _jws.add_signature(key=key, alg=alg.value, protected=json.dumps(protected_header))
    return _jws.serialize(compact=compact).encode()


def create_tls_fed_metadata(
    entity_id: str,
    client_cert: str,
    cache_ttl: int = 3600,
    organization_id: str = 'SE0123456789',
    scopes: Optional[List[str]] = None,
) -> TLSFEDMetadata:

    if scopes is None:
        scopes = list()

    entities = [
        Entity.parse_obj(
            {
                'entity_id': entity_id,
                'organization': 'Test Org',
                'organization_id': organization_id,
                'issuers': [
                    {'x509certificate': f'-----BEGIN CERTIFICATE-----\n{client_cert}\n-----END CERTIFICATE-----'}
                ],
                'extensions': {RegisteredExtensions.SAML_SCOPE: {'scope': scopes}},
            }
        )
    ]
    return TLSFEDMetadata(version='1.0.0', cache_ttl=cache_ttl, entities=entities)
