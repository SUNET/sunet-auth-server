# -*- coding: utf-8 -*-
from base64 import urlsafe_b64encode
from typing import Optional, Union

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from fastapi import HTTPException
from jwcrypto import jwk, jws
from jwcrypto.common import base64url_decode, base64url_encode
from loguru import logger
from pydantic import ValidationError

from auth_server.config import load_config
from auth_server.context import ContextRequest
from auth_server.models.gnap import Client, ContinueRequest, GNAPJOSEHeader, GrantRequest, Key
from auth_server.models.jose import JWK, SupportedAlgorithms, SupportedJWSType
from auth_server.time_utils import utc_now
from auth_server.utils import hash_with

__author__ = "lundberg"


async def choose_hash_alg(alg: SupportedAlgorithms):
    # TODO: what about EdDSA
    if alg.name.endswith("256"):
        return SHA256()
    elif alg.name.endswith("384"):
        return SHA384()
    elif alg.name.endswith("512"):
        return SHA512()
    else:
        raise NotImplementedError(f"No hash alg mapped to {alg}")


async def verify_gnap_jws(
    request: ContextRequest, gnap_key: Key, jws_header: GNAPJOSEHeader, access_token: Optional[str] = None
) -> bool:
    config = load_config()

    # Please mypy
    if not isinstance(gnap_key.jwk, JWK):
        raise RuntimeError("key needs to be of type jose.JWK")

    # The header of the JWS MUST contain the "kid" field of the key bound to this client instance for this request.
    if gnap_key.jwk.kid != jws_header.kid:
        logger.error(f"kid mismatch. grant: {gnap_key.jwk.kid} != header: {jws_header.kid}")
        raise HTTPException(status_code=400, detail="key id is not the same in request as in header")

    # Verify that the request is reasonably fresh
    if utc_now() - jws_header.created > config.proof_jws_max_age:
        logger.error(f"jws is to old: {utc_now() - jws_header.created} > {config.proof_jws_max_age}")
        raise HTTPException(status_code=400, detail=f"jws is to old: >{config.proof_jws_max_age}")

    # The HTTP Method used to make this request, as an uppercase ASCII string.
    if request.method != jws_header.htm.value:
        logger.error(f"http method mismatch. request: {request.method} != header: {jws_header.htm.value}")
        raise HTTPException(status_code=400, detail="http method does not match")

    # The HTTP URI used for this request, including all path and query components.
    if request.url != jws_header.uri:
        logger.error(f"http uri mismatch. request: {request.url} != header: {jws_header.uri}")
        raise HTTPException(status_code=400, detail="http uri does not match")

    # The hashed access token used for this request
    # The result of Base64url encoding (with no padding) of the SHA-256 digest of the ASCII encoding of the
    # associated access token's value.
    if access_token is not None:
        access_token_hash = hash_with(SHA256(), access_token.encode())
        b64_access_token_hash = urlsafe_b64encode(access_token_hash).decode("utf-8").rstrip("=")
        if b64_access_token_hash != jws_header.ath:
            logger.error(f"ath mismatch. calculated ath: {b64_access_token_hash} != header: {jws_header.ath}")
            raise HTTPException(status_code=400, detail="ath does not match")
    return True


async def check_jws_proof(
    request: ContextRequest,
    gnap_key: Key,
    access_token: Optional[str] = None,
) -> bool:
    # Verify jws
    if request.context.jws_obj is None:
        raise HTTPException(status_code=400, detail="No JWS found")

    verify_jws(jws_obj=request.context.jws_obj, gnap_key=gnap_key)

    # Parse jws header
    try:
        jws_header = GNAPJOSEHeader(**request.context.jws_obj.jose_header)
    except ValidationError as e:
        logger.error("Missing JWS header")
        raise HTTPException(status_code=400, detail=f"Missing JWS header: {e}")

    if jws_header.typ is not SupportedJWSType.JWS:
        raise HTTPException(status_code=400, detail=f"typ should be {SupportedJWSType.JWS}")

    return await verify_gnap_jws(request=request, gnap_key=gnap_key, jws_header=jws_header, access_token=access_token)


async def check_jwsd_proof(
    request: ContextRequest,
    gnap_key: Key,
    access_token: Optional[str] = None,
) -> bool:
    if request.context.detached_jws is None or request.context.detached_jws_body is None:
        raise HTTPException(status_code=400, detail="No detached JWS found")

    logger.debug(f"detached_jws: {request.context.detached_jws}")
    logger.debug(f"detached_jws_body: {request.context.detached_jws_body}")

    # recreate jws
    try:
        header, client_payload_hash, signature = request.context.detached_jws.split(".")
    except ValueError as e:
        logger.error(f"invalid detached jws: {e}")
        raise HTTPException(status_code=400, detail="invalid format for detached jws")

    payload = base64url_encode(request.context.detached_jws_body)
    logger.debug(f"payload: {payload}")

    # check hash of payload
    payload_hash = hash_with(SHA256(), request.context.detached_jws_body.encode())
    if payload_hash != base64url_decode(client_payload_hash):
        logger.error(f"invalid payload hash: {repr(payload_hash)}")
        raise HTTPException(status_code=400, detail="invalid payload hash")

    raw_jws = f"{header}.{payload}.{signature}"
    logger.debug(f"raw_jws: {raw_jws}")

    # deserialize jws
    _jws = jws.JWS()
    try:
        _jws.deserialize(raw_jws=raw_jws)
        logger.info("Detached JWS token deserialized")
        logger.debug(f"JWS: {_jws.objects}")
    except jws.InvalidJWSObject as e:
        logger.error(f"Failed to deserialize detached jws: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    verify_jws(jws_obj=_jws, gnap_key=gnap_key)

    try:
        jws_header = GNAPJOSEHeader(**_jws.jose_header)
    except ValidationError as e:
        logger.error(f"Missing Detached JWS header: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    if jws_header.typ is not SupportedJWSType.JWSD:
        raise HTTPException(status_code=400, detail=f"typ should be {SupportedJWSType.JWSD}")

    return await verify_gnap_jws(request=request, gnap_key=gnap_key, jws_header=jws_header, access_token=access_token)


def verify_jws(jws_obj: jws.JWS, client_key: Optional[jwk.JWK] = None, gnap_key: Optional[Key] = None) -> bool:
    if gnap_key is not None and gnap_key.jwk is not None:
        client_key = jws.JWK(**gnap_key.jwk.dict(exclude_unset=True))
    if client_key is not None:
        try:
            jws_obj.verify(client_key)
            logger.info("JWS token verified")
            return True
        except jws.InvalidJWSSignature as e:
            logger.error(f"JWS signature failure: {e}")
            raise HTTPException(status_code=400, detail="JWS signature could not be verified")
    else:
        raise HTTPException(status_code=400, detail="no client key found")
