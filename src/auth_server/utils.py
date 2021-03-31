# -*- coding: utf-8 -*-
import json
import logging
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.x509 import Certificate, load_pem_x509_certificate
from jwcrypto import jwk

from auth_server.config import load_config

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


@lru_cache()
def load_jwks() -> jwk.JWKSet:
    config = load_config()
    if config.keystore_path.exists():
        with open(config.keystore_path, 'r') as f:
            jwks = jwk.JWKSet.from_json(f.read())
            logger.info(f'jwks loaded from {config.keystore_path}')
    else:
        logger.info('Creating new jwks')
        key = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')
        jwks = jwk.JWKSet()
        jwks.add(key)
        with open(config.keystore_path, 'w') as f:
            json.dump(jwks.export(as_dict=True), f)
            logger.info(f'jwks written to {config.keystore_path}')
    return jwks


@lru_cache()
def get_signing_key() -> jwk.JWK:
    jwks = load_jwks()
    # Hack to be backwards compatible with thiss-auth
    # TODO: use jwks.get_key('default')
    signing_key = list(jwks['keys'])[0]
    return signing_key


def load_cert_from_str(cert: str) -> Certificate:
    raw_cert = f'-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----'
    return load_pem_x509_certificate(raw_cert.encode())
