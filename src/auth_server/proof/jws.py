# -*- coding: utf-8 -*-
import logging

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from fastapi import HTTPException
from jwcrypto import jws
from jwcrypto.common import base64url_encode
from pydantic import ValidationError

from auth_server.config import load_config
from auth_server.context import ContextRequest
from auth_server.models.gnap import Client, GrantRequest, Key
from auth_server.models.jose import JWK, JWSHeader, JWSType, SupportedAlgorithms
from auth_server.time_utils import utc_now

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


async def verify_gnap_jws(request: ContextRequest, grant_request: GrantRequest, jws_header: JWSHeader) -> bool:
    config = load_config()

    # Please mypy
    if not isinstance(grant_request.client, Client):
        raise RuntimeError('client needs to be of type gnap.Client')
    if not isinstance(grant_request.client.key, Key):
        raise RuntimeError('key needs to be of type gnap.Key')
    if not isinstance(grant_request.client.key.jwk, JWK):
        raise RuntimeError('key needs to be of type jose.JWK')

    # The header of the JWS MUST contain the "kid" field of the key bound to this client instance for this request.
    if grant_request.client.key.jwk.kid != jws_header.kid:
        logger.error(f'kid mismatch. grant: {grant_request.client.key.jwk.kid} != header: {jws_header.kid}')
        raise HTTPException(status_code=400, detail='key id is not the same in request as in header')

    # Verify that the request is reasonably fresh
    if utc_now() - jws_header.created > config.proof_jws_max_age:
        logger.error(f'jws is to old: {utc_now() - jws_header.created} > {config.proof_jws_max_age}')
        raise HTTPException(status_code=400, detail=f'jws is to old: >{config.proof_jws_max_age}')

    # The HTTP Method used to make this request, as an uppercase ASCII string.
    if request.method != jws_header.htm.value:
        logger.error(f'http method mismatch. request: {request.method} != header: {jws_header.htm.value}')
        raise HTTPException(status_code=400, detail='http method does not match')

    # The HTTP URI used for this request, including all path and query components.
    if request.url != jws_header.uri:
        logger.error(f'http uri mismatch. request: {request.url} != header: {jws_header.uri}')
        raise HTTPException(status_code=400, detail='http uri does not match')

    # TODO: figure out when if verify ath

    return True


async def check_jws_proof(request: ContextRequest, grant_request: GrantRequest, jws_header: JWSHeader) -> bool:
    if request.context.jws_verified:
        if jws_header.typ is not JWSType.JWS:
            raise HTTPException(status_code=400, detail=f'typ should be {JWSType.JWS}')
        return await verify_gnap_jws(request=request, grant_request=grant_request, jws_header=jws_header)
    return False


async def check_jwsd_proof(request: ContextRequest, grant_request: GrantRequest, detached_jws: str) -> bool:
    # Please mypy
    if not isinstance(grant_request.client, Client):
        raise RuntimeError('client needs to be of type gnap.Client')
    if not isinstance(grant_request.client.key, Key):
        raise RuntimeError('key needs to be of type gnap.Key')

    logger.debug(f'detached_jws: {detached_jws}')
    header, signature = detached_jws.split('.')
    payload = base64url_encode(grant_request.json(exclude_unset=True))
    raw_jws = f'{header}.{payload}.{signature}'
    _jws = jws.JWS()
    _jws.deserialize(raw_jws=raw_jws)
    logger.info('Detached JWS token deserialized')
    logger.debug(f'JWS: {_jws.objects}')

    # Verify jws
    client_key = None
    if grant_request.client.key.jwk is not None:
        client_key = jws.JWK(**grant_request.client.key.jwk.dict(exclude_unset=True))
    if client_key is not None:
        try:
            _jws.verify(client_key)
            logger.info('Detached JWS token verified')
        except jws.InvalidJWSSignature as e:
            logger.error(f'JWS signature failure: {e}')
            raise HTTPException(status_code=400, detail='detached JWS signature could not be verified')
    else:
        raise HTTPException(status_code=400, detail='no client key found')

    try:
        jws_header = JWSHeader(**_jws.jose_header)
    except ValidationError as e:
        logger.error(f'Missing Detached JWS header: {e}')
        raise HTTPException(status_code=400, detail=str(e))

    if jws_header.typ is not JWSType.JWSD:
        raise HTTPException(status_code=400, detail=f'typ should be {JWSType.JWSD}')

    return await verify_gnap_jws(request=request, grant_request=grant_request, jws_header=jws_header)
