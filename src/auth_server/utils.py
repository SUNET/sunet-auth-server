# -*- coding: utf-8 -*-
import importlib
import json
import logging
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping, Sequence, Union

from cryptography.x509 import Certificate, load_pem_x509_certificate
from jwcrypto import jwk

from auth_server.config import load_config

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


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


def import_class(class_path: str) -> Callable:
    path_split = class_path.split('.')
    module_path = '.'.join(path_split[:-1])
    class_name = path_split[-1]
    module = importlib.import_module(module_path)
    klass = getattr(module, class_name)
    return klass


def get_values(key: str, obj: Union[Mapping, Sequence]) -> Iterable[Any]:
    """
    Recurse through a dict like object and return all values for the specified key

    :param key: key to look for
    :param obj: structure to search in
    :return: iterator of values
    """
    if isinstance(obj, dict):
        if key in obj:
            yield obj[key]
        for value in obj.values():
            for hit in get_values(key, value):
                yield hit
    elif isinstance(obj, list):
        for item in obj:
            for hit in get_values(key, item):
                yield hit
