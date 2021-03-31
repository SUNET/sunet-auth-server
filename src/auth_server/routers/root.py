# -*- coding: utf-8 -*-

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.auth_methods.base import lookup_client_key
from auth_server.auth_methods.mtls import check_mtls_proof
from auth_server.config import AuthServerConfig, load_config
from auth_server.models.gnap import Client, GrantRequest, GrantResponse, Proof, ResponseAccessToken
from auth_server.models.jose import JWKS, Claims, JWKTypes
from auth_server.utils import get_signing_key, load_jwks

__author__ = 'lundberg'


logger = logging.getLogger(__name__)

root_router = APIRouter(prefix='')


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
    grant_req: GrantRequest,
    tls_client_cert: Optional[str] = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
):
    key_reference = None

    if not isinstance(grant_req.client, Client):
        raise HTTPException(status_code=400, detail='client by reference not implemented')

    # Key sent by reference, look it up
    if isinstance(grant_req.client.key, str):
        logger.debug(f'key reference: {grant_req.client.key}')
        key_reference = grant_req.client.key
        grant_req.client.key = await lookup_client_key(key_id=grant_req.client.key, config=config)

    if grant_req.client.key.proof is Proof.MTLS:
        if tls_client_cert is None:
            raise HTTPException(status_code=400, detail='no client certificate found')
        proof_ok = await check_mtls_proof(grant_request=grant_req, cert=tls_client_cert)
    elif grant_req.client.key.proof is Proof.HTTPSIGN:
        raise HTTPException(status_code=400, detail='httpsign is not implemented')
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
        logger.info(f'OK:{key_reference}:{config.audience}')
        return auth_response

    return HTTPException(status_code=401, detail='permission denied')
