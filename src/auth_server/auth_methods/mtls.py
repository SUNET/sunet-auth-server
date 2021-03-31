# -*- coding: utf-8 -*-

import logging
from base64 import b64encode

from cryptography.hazmat.primitives.hashes import SHA256
from fastapi import HTTPException

from auth_server.models.gnap import Client, GrantRequest, Key
from auth_server.utils import load_cert_from_str

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


async def check_mtls_proof(grant_request: GrantRequest, cert: str) -> bool:
    proof_ok = False
    tls_cert = load_cert_from_str(cert)
    tls_fingerprint = b64encode(tls_cert.fingerprint(algorithm=SHA256())).decode('utf-8')
    logger.debug(f'tls cert fingerprint: {str(tls_fingerprint)}')

    if not isinstance(grant_request.client, Client):
        raise HTTPException(status_code=400, detail='Client reference not implemented')
    if not isinstance(grant_request.client.key, Key):
        raise HTTPException(status_code=500, detail='Client key unexpected a reference')

    if grant_request.client.key.cert_S256 is not None:
        logger.debug(f'cert#S256: {grant_request.client.key.cert_S256}')
        if tls_fingerprint == grant_request.client.key.cert_S256:
            logger.info(f'TLS cert fingerprint matches grant request cert#S256')
            proof_ok = True
    elif grant_request.client.key.cert is not None:
        grant_cert = load_cert_from_str(grant_request.client.key.cert)
        grant_cert_fingerprint = b64encode(grant_cert.fingerprint(algorithm=SHA256())).decode('utf-8')
        logger.debug(f'grant cert fingerprint: {grant_cert_fingerprint}')
        if tls_fingerprint == grant_cert_fingerprint:
            logger.info(f'TLS cert fingerprint matches grant request cert fingerprint')
            proof_ok = True

    return proof_ok
