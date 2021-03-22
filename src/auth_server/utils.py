# -*- coding: utf-8 -*-
import json
import logging
from datetime import datetime, timezone

from cryptography.x509 import load_pem_x509_certificate
from jwcrypto import jwk

from auth_server.config import AuthServerConfig

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def load_jwks(config: AuthServerConfig) -> jwk.JWKSet:
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


def get_signing_key(jwks: jwk.JWKSet) -> jwk.JWK:
    # Hack to be backwards compatible with thiss-auth
    # TODO: use jwks.get_key('default')
    signing_key = list(jwks['keys'])[0]
    return signing_key


def load_client_cert(ssl_client_cert: str):
    raw_cert = f'-----BEGIN CERTIFICATE-----\n{ssl_client_cert}\n-----END CERTIFICATE-----'
    return load_pem_x509_certificate(raw_cert.encode())
