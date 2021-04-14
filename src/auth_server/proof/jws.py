# -*- coding: utf-8 -*-
import base64
import json
import logging

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512, Hash
from fastapi import HTTPException
from jwcrypto import jws
from pydantic import ValidationError

from auth_server.config import load_config
from auth_server.context import ContextRequest
from auth_server.models.gnap import Client, GrantRequest, Key
from auth_server.models.jose import JWK, JWSHeaders, SupportedAlgorithms
from auth_server.utils import utc_now

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


async def choose_hash_alg(alg: SupportedAlgorithms):
    # TODO: what about EdDSA
    if alg.name.endswith('256'):
        return SHA256()
    elif alg.name.endswith('384'):
        return SHA384()
    elif alg.name.endswith('512'):
        return SHA512()
    else:
        raise NotImplementedError(f'No hash alg mapped to {alg}')


async def check_at_hash(access_token: str, alg: SupportedAlgorithms, at_hash: str) -> bool:
    """
    at_hash value is the base64url encoding of the left-most half of the hash of the octets of the ASCII
    representation of the "access_token" value ex. if the "alg" is "RS256", hash the "access_token"
    value with SHA-256, then take the left-most 128 bits and base64url encode them.
    """
    hash_alg = await choose_hash_alg(alg)
    logger.debug(f'chosen hash alg: {hash_alg}')
    digest = Hash(hash_alg)
    digest.update(access_token.encode())
    digest_bytes = digest.finalize()
    computed_at_hash = base64.b64encode(digest_bytes[: hash_alg.digest_size // 2]).decode('utf-8')
    if at_hash == computed_at_hash:
        return True
    logger.debug(f'computed at_hash: {computed_at_hash}, supplied at_hash: {at_hash}')
    return False


async def verify_gnap_jws(request: ContextRequest, grant_request: GrantRequest, jws_headers: JWSHeaders) -> bool:
    config = load_config()

    # Please mypy
    if not isinstance(grant_request.client, Client):
        raise RuntimeError('client needs to be of type gnap.Client')
    if not isinstance(grant_request.client.key, Key):
        raise RuntimeError('key needs to be of type gnap.Key')
    if not isinstance(grant_request.client.key.jwk, JWK):
        raise RuntimeError('key needs to be of type jose.JWK')

    # The header of the JWS MUST contain the "kid" field of the key bound to this client instance for this request.
    if grant_request.client.key.jwk.kid != jws_headers.kid:
        logger.error(f'kid mismatch. grant: {grant_request.client.key.jwk.kid} != header: {jws_headers.kid}')
        raise HTTPException(status_code=400, detail='key id is not the same in request as in header')

    # Verify that the request is reasonably fresh
    if utc_now() - jws_headers.ts > config.jws_max_age:
        logger.error(f'jws is to old: {utc_now() - jws_headers.ts} > {config.jws_max_age}')
        raise HTTPException(status_code=400, detail=f'jws is to old: >{config.jws_max_age}')

    # The HTTP Method used to make this request, as an uppercase ASCII string.
    if request.method != jws_headers.htm.value:
        logger.error(f'http method mismatch. request: {request.method} != header: {jws_headers.htm.value}')
        raise HTTPException(status_code=400, detail='http method does not match')

    # The HTTP URI used for this request, including all path and query components.
    if request.url != jws_headers.htu:
        logger.error(f'http uri mismatch. request: {request.url} != header: {jws_headers.htu}')
        raise HTTPException(status_code=400, detail='http uri does not match')

    # Check at_hash value
    access_token_str = json.dumps(grant_request.dict(exclude_unset=True)['access_token'])
    if not await check_at_hash(access_token_str, jws_headers.alg, jws_headers.at_hash):
        logger.error(f'at_hash mismatch')
        raise HTTPException(status_code=400, detail='at_hash does not match')

    return True


async def check_jws_proof(request: ContextRequest, grant_request: GrantRequest, jws_headers: JWSHeaders) -> bool:
    if request.context.jws_verified:
        return await verify_gnap_jws(request=request, grant_request=grant_request, jws_headers=jws_headers)
    return False


async def check_jwsd_proof(request: ContextRequest, grant_request: GrantRequest, detached_jws: str) -> bool:
    # Please mypy
    if not isinstance(grant_request.client, Client):
        raise RuntimeError('client needs to be of type gnap.Client')
    if not isinstance(grant_request.client.key, Key):
        raise RuntimeError('key needs to be of type gnap.Key')

    logger.debug(f'detached_jws: {detached_jws}')
    jws_parts = detached_jws.split('.')
    payload = grant_request.json(exclude_unset=True, exclude_defaults=True, exclude_none=True)
    jws_parts[1] = payload
    jwstoken = jws.JWS()
    jwstoken.deserialize('.'.join(jws_parts))
    logger.info('Detached JWS token deserialized')
    logger.debug(f'JWS: {jwstoken.objects}')

    # Verify jws
    client_key = None
    if grant_request.client.key.jwk is not None:
        client_key = jws.JWK(**grant_request.client.key.jwk.dict(exclude_unset=True))
    if client_key is not None:
        try:
            jwstoken.verify(client_key)
            logger.info('Detached JWS token verified')
        except jws.InvalidJWSSignature as e:
            logger.error(f'JWS signature failure: {e}')
            raise HTTPException(status_code=400, detail='detached JWS signature could not be verified')
    else:
        raise HTTPException(status_code=400, detail='no client key found')

    try:
        jws_headers = JWSHeaders(**jwstoken.jose_header)
    except ValidationError as e:
        logger.error('Missing Detached JWS header')
        raise HTTPException(status_code=400, detail=str(e))

    return await verify_gnap_jws(request=request, grant_request=grant_request, jws_headers=jws_headers)
