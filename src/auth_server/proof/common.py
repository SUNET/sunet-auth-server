# -*- coding: utf-8 -*-

from typing import Optional

from loguru import logger

from auth_server.config import ClientKey, ConfigurationError, load_config
from auth_server.models.gnap import Key
from auth_server.models.jose import ECJWK, RSAJWK, KeyType, SymmetricJWK

__author__ = "lundberg"


async def load_config_key(client_key: ClientKey) -> Key:
    logger.info("Trying to load client key from config")
    logger.debug(f"client_key: {client_key}")

    # JWK
    if client_key.jwk:
        logger.info("Loading JWK from config")
        logger.debug(f"client_key.jwk: {client_key.jwk}")
        if client_key.jwk.kty is KeyType.EC:
            return Key(proof=client_key.proof, jwk=ECJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.RSA:
            return Key(proof=client_key.proof, jwk=RSAJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.OCT:
            return Key(proof=client_key.proof, jwk=SymmetricJWK(**client_key.jwk.dict(exclude_unset=True)))
        else:
            logger.error(f"JWK type {client_key.jwk.kty} not implemented")
            raise NotImplementedError(f"JWK type {client_key.jwk.kty} not implemented")
    # cert
    elif client_key.cert:
        logger.info("Loading cert from config")
        logger.debug(f"client_key.cert: {client_key.cert}")
        return Key(proof=client_key.proof, cert=client_key.cert)
    # cert#S256
    elif client_key.cert_S256:
        logger.info("Loading cert_S256 from config")
        logger.debug(f"client_key.cert_S256: {client_key.cert_S256}")
        return Key(proof=client_key.proof, cert_S256=client_key.cert_S256)

    raise ConfigurationError(f"malformed client key in config")


async def lookup_client_key_from_config(key_reference: str) -> Optional[Key]:
    config = load_config()
    client_key = None

    # Look for a key in config
    if key_reference in config.client_keys:
        client_key = await load_config_key(config.client_keys[key_reference])

    return client_key
