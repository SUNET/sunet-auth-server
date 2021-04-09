# -*- coding: utf-8 -*-

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.auth_methods.base import lookup_client_key
from auth_server.auth_methods.jws import check_jws_proof, check_jwsd_proof
from auth_server.auth_methods.mtls import check_mtls_proof
from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.models.gnap import Client, GrantRequest, GrantResponse, Proof, ResponseAccessToken
from auth_server.models.jose import JWKS, Claims, JWKTypes
from auth_server.utils import get_signing_key, load_jwks

__author__ = 'lundberg'


logger = logging.getLogger(__name__)

root_router = APIRouter(route_class=ContextRequestRoute, prefix='')


@root_router.get('/.well-known/jwks.json', response_model=JWKS, response_model_exclude_unset=True)
async def get_jwks(jwks: JWKSet = Depends(load_jwks)):
    jwks = jwks.export(private_keys=False, as_dict=True)
    return jwks


@root_router.get('/.well-known/jwk.json', response_model=JWKTypes, response_model_exclude_unset=True)
async def get_jwk(signing_key: JWK = Depends(get_signing_key)):
    return signing_key.export(private_key=False, as_dict=True)


@root_router.get('/.well-known/public.pem', response_class=Response)
async def get_public_pem(signing_key: JWK = Depends(get_signing_key)):
    data = signing_key.export_to_pem(private_key=False)
    return Response(content=data, media_type='application/x-pem-file')


@root_router.post('/transaction', response_model=GrantResponse, response_model_exclude_unset=True)
async def transaction(
    request: ContextRequest,
    grant_req: GrantRequest,
    tls_client_cert: Optional[str] = Header(None),
    detached_jws: Optional[str] = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
):

    if not isinstance(grant_req.client, Client):
        raise HTTPException(status_code=400, detail='client by reference not implemented')

    if isinstance(grant_req.client.key, str):
        # Key sent by reference, look it up
        logger.debug(f'key reference: {grant_req.client.key}')
        request.context.key_id = grant_req.client.key
        grant_req.client.key = await lookup_client_key(key_id=grant_req.client.key, config=config)

    # TODO: This part could probably move to it's own function/module
    if grant_req.client.key.proof is Proof.MTLS:
        if tls_client_cert is None:
            raise HTTPException(status_code=400, detail='no client certificate found')
        proof_ok = await check_mtls_proof(grant_request=grant_req, cert=tls_client_cert)
    elif grant_req.client.key.proof is Proof.HTTPSIGN:
        raise HTTPException(status_code=400, detail='httpsign is not implemented')
    elif grant_req.client.key.proof is Proof.JWS and request.context.jws_verified:
        proof_ok = await check_jws_proof(grant_request=grant_req, jws_headers=request.context.jws_headers)
    elif grant_req.client.key.proof is Proof.JWSD and detached_jws:
        proof_ok = await check_jwsd_proof(grant_request=grant_req, detached_jws=detached_jws)
    elif grant_req.client.key.proof is Proof.TEST and config.test_mode is True:
        logger.warning(f'TEST_MODE - access token will be returned with no proof')
        proof_ok = True
    else:
        raise HTTPException(status_code=400, detail='no supported proof method')

    if proof_ok:
        # TODO: We need something like a policy engine to call for creation of an access token
        # Create access token
        claims = Claims(exp=config.expires_in, aud=config.audience)
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
        token.make_signed_token(signing_key)
        auth_response = GrantResponse(access_token=ResponseAccessToken(bound=False, value=token.serialize()))
        logger.info(f'OK:{request.context.key_id}:{config.audience}')
        return auth_response

    raise HTTPException(status_code=401, detail='permission denied')
