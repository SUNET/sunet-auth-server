# -*- coding: utf-8 -*-

import logging
from typing import Optional

from auth_server.config import ClientKey, load_config
from auth_server.context import ContextRequest
from auth_server.models.gnap import Key
from auth_server.models.jose import ECJWK, RSAJWK, KeyType, SymmetricJWK

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


async def load_config_key(client_key: ClientKey) -> Key:
    logger.info('Trying to load client key from config')
    logger.debug(f'client_key: {client_key}')

    # JWK
    if client_key.jwk:
        logger.info('Loading JWK from config')
        logger.debug(f'client_key.jwk: {client_key.jwk}')
        if client_key.jwk.kty is KeyType.EC:
            return Key(proof=client_key.proof, jwk=ECJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.RSA:
            return Key(proof=client_key.proof, jwk=RSAJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.OCT:
            return Key(proof=client_key.proof, jwk=SymmetricJWK(**client_key.jwk.dict(exclude_unset=True)))
        else:
            logger.error(f'JWK type {client_key.jwk.kty} not implemented')
            raise NotImplementedError(f'JWK type {client_key.jwk.kty} not implemented')
    # cert
    elif client_key.cert:
        logger.info('Loading cert from config')
        logger.debug(f'client_key.cert: {client_key.cert}')
        return Key(proof=client_key.proof, cert=client_key.cert)
    # cert#S256
    elif client_key.cert_S256:
        logger.info('Loading cert_S256 from config')
        logger.debug(f'client_key.cert_S256: {client_key.cert_S256}')
        return Key(proof=client_key.proof, cert_S256=client_key.cert_S256)

    raise RuntimeError(f'malformed client key in config')


async def lookup_client_key_from_config(request: ContextRequest, key_id: str) -> Optional[Key]:
    config = load_config()
    request.context.key_reference = key_id  # Remember the key reference for later use
    client_key = None
    logger.info(f'Trying to load key with key id: {key_id}')

    # Look for a key in config
    if key_id in config.client_keys:
        logger.info('Trying to load key from config')
        client_key = await load_config_key(config.client_keys[key_id])

    return client_key
