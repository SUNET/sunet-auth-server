# -*- coding: utf-8 -*-
import importlib
import json
import logging
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable, Generator, Mapping, Sequence, Union
from uuid import uuid4

import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA3_256, SHA3_384, SHA3_512, SHA256, SHA512, HashAlgorithm
from jwcrypto import jwk

from auth_server.config import ConfigurationError, load_config
from auth_server.models.gnap import HashMethod

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


@lru_cache()
def load_jwks() -> jwk.JWKSet:
    config = load_config()
    if config.keystore_path.exists():
        with open(config.keystore_path, "r") as f:
            jwks = jwk.JWKSet.from_json(f.read())
            logger.info(f"jwks loaded from {config.keystore_path}")
    else:
        logger.info("Creating new jwks")
        key = jwk.JWK.generate(kid="default", kty="EC", crv="P-256")
        jwks = jwk.JWKSet()
        jwks.add(key)
        with open(config.keystore_path, "w") as f:
            json.dump(jwks.export(as_dict=True), f)
            logger.info(f"jwks written to {config.keystore_path}")
    return jwks


@lru_cache()
def get_signing_key() -> jwk.JWK:
    config = load_config()
    jwks = load_jwks()
    signing_key = jwks.get_key(config.signing_key_id)
    if signing_key is None:
        raise ConfigurationError(f"no JWK with id {config.signing_key_id} found in JWKS")
    return signing_key


def import_class(class_path: str) -> Callable:
    path_split = class_path.split(".")
    module_path = ".".join(path_split[:-1])
    class_name = path_split[-1]
    module = importlib.import_module(module_path)
    klass = getattr(module, class_name)
    return klass


def get_values(key: str, obj: Union[Mapping, Sequence]) -> Generator[Any, None, None]:
    """
    Recurse through a dict-like object and return all values for the specified key

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


def get_hex_uuid4(length=32) -> str:
    if length > 32:
        raise ValueError("Max length is 32")
    return uuid4().hex[:length]


def get_hash_by_name(hash_name: str) -> HashAlgorithm:
    supported_hash_algs = [SHA256(), SHA512(), SHA3_256(), SHA3_384(), SHA3_512()]
    if hash_name in {"sha-256", "sha-512"}:
        # IANA says sha-256, cryptography says sha256...
        hash_name = hash_name.replace("-", "")
    for alg in supported_hash_algs:
        if alg.name == hash_name:
            return alg
    raise NotImplementedError(f"Hash algorithm {hash_name} not implemented")


def hash_with(hash_alg: HashAlgorithm, data: bytes) -> bytes:
    h = hashes.Hash(hash_alg)
    h.update(data)
    return h.finalize()


def get_interaction_hash(
    client_nonce: str,
    as_nonce: str,
    interact_ref: str,
    transaction_url: str,
    hash_method: HashMethod = HashMethod.SHA_256,
) -> str:
    """
    To calculate the "hash" value, the party doing the calculation
    creates a hash string by concatenating the following values in the
    following order using a single newline ("\\n") character to separate
    them:

    *  the "nonce" value sent by the client instance in the interaction
      "finish" section of the initial request (Section 2.5.2)

    *  the AS's nonce value from the interaction finish response
      (Section 3.3.4)

    *  the "interact_ref" returned from the AS as part of the interaction
      finish method (Section 4.2)

    *  the grant endpoint URL the client instance used to make its
      initial request (Section 2)

    There is no padding or whitespace before or after any of the lines,
    and no trailing newline character.

    VJLO6A4CATR0KRO
    MBDOFXG4Y5CVJCX821LH
    4IFWWIKYB2PQ6U56NL1
    https://server.example.com/tx

    results in: x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY

    The party then hashes this string with the appropriate algorithm
    based on the "hash_method" parameter of the "callback".  If the
    "hash_method" value is not present in the client instance's request,
    the algorithm defaults to "sha-256". The resulting byte array from
    the hash function is then encoded using URL-Safe Base64 with no padding.

    https://datatracker.ietf.org/doc/html/draft-ietf-gnap-core-protocol-16#section-4.2.3
    """
    hash_alg = get_hash_by_name(hash_name=hash_method.value)
    plaintext = f"{client_nonce}\n{as_nonce}\n{interact_ref}\n{transaction_url}".encode()
    hash_res = hash_with(hash_alg, plaintext)
    return urlsafe_b64encode(hash_res).decode(encoding="utf-8").rstrip("=")


async def push_interaction_finish(url: str, interaction_hash: str, interaction_reference: str) -> None:
    logger.debug(f"Trying interaction PUSH finish to {url}")
    body = {"hash": interaction_hash, "interact_ref": interaction_reference}
    try:
        async with aiohttp.ClientSession() as session:
            response = await session.post(url=url, json=body)
    except aiohttp.ClientError as e:
        logger.error(f"PUSH finish to {url} failed: {e}")
        return None
    if response.status != 200:
        logger.error(f"PUSH finish to {url} returned {response.status}")
        return None
    logger.info(f"Successfully delivered interaction PUSH finish to {url}")
