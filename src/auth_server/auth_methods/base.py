# -*- coding: utf-8 -*-

import logging
from base64 import b64encode

from cryptography.hazmat.primitives.hashes import SHA256
from fastapi import HTTPException

from auth_server.config import AuthServerConfig
from auth_server.mdq import KeyUse, xml_mdq_get
from auth_server.models.gnap import Key, Proof

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


async def lookup_client_key(key_id: str, config: AuthServerConfig) -> Key:
    # TODO: Look for the key id in config also
    mdq_certs = await xml_mdq_get(entity_id=key_id, mdq_url=config.mdq_server)
    if not mdq_certs:
        raise HTTPException(status_code=400, detail=f'{key_id} not found')

    client_cert = [item.cert for item in mdq_certs if item.use == KeyUse.SIGNING]
    if not client_cert:
        raise HTTPException(status_code=400, detail=f'No signing key found for {key_id}')

    logger.info(f'found cert in metadata for {key_id}')
    return Key(proof=Proof.MTLS, cert_S256=b64encode(client_cert[0].fingerprint(algorithm=SHA256())).decode('utf-8'))
