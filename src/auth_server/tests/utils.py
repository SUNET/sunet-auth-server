# -*- coding: utf-8 -*-

import json
from datetime import datetime, timedelta
from pathlib import PurePath
from typing import Optional

from jwcrypto import jwk, jws

from auth_server.models.jose import SupportedAlgorithms
from auth_server.models.tls_fed_metadata import Entity
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadata
from auth_server.utils import utc_now

__author__ = 'lundberg'


def tls_fed_metadata_to_jws(
    metadata: TLSFEDMetadata,
    key: jwk.JWK,
    issuer: str,
    expires: timedelta,
    alg: SupportedAlgorithms,
    issue_time: Optional[datetime] = None,
) -> bytes:
    payload = metadata.json(exclude_unset=True)
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
    return _jws.serialize(compact=True).encode()


def create_tls_fed_metadata(
    datadir: PurePath, entity_id: str, client_cert: str, organization_id: str = 'SE0123456789'
) -> TLSFEDMetadata:
    _jwks = jwk.JWKSet()
    with open(f'{datadir}/tls_fed_jwks.json', 'r') as f:
        _jwks.import_keyset(f.read())

    entities = [
        Entity.parse_obj(
            {
                'entity_id': entity_id,
                'organization': 'Test Org',
                'organization_id': organization_id,
                'scopes': ['test.localhost'],
                'issuers': [
                    {'x509certificate': f'-----BEGIN CERTIFICATE-----\n{client_cert}\n-----END CERTIFICATE-----'}
                ],
            }
        )
    ]
    return TLSFEDMetadata(version='1.0.0', cache_ttl=3600, entities=entities)
