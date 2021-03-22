# -*- coding: utf-8 -*-

import logging
from typing import Optional, Union

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate
from fastapi import APIRouter, Header, HTTPException
from jwcrypto import jwt
from starlette.requests import Request
from starlette.responses import Response

from auth_server.mdq import xml_mdq_get
from auth_server.models import (
    ECJWK,
    JWK,
    JWKS,
    RSAJWK,
    AccessToken,
    AuthRequest,
    AuthResponse,
    Claims,
    Proof,
    SymmetricJWK,
)
from auth_server.utils import get_signing_key, load_client_cert

__author__ = 'lundberg'


logger = logging.getLogger(__name__)

root_router = APIRouter(prefix='')


@root_router.get('/.well-known/jwks.json', response_model=JWKS, response_model_exclude_unset=True)
async def get_jwks(request: Request):
    jwks = request.app.state.jwks.export(private_keys=False, as_dict=True)
    return jwks


@root_router.get(
    '/.well-known/jwk.json', response_model=Union[ECJWK, RSAJWK, SymmetricJWK], response_model_exclude_unset=True
)
async def get_jwk(request: Request):
    signing_key = get_signing_key(request.app.state.jwks)
    return signing_key.export(private_key=False, as_dict=True)


@root_router.get('/.well-known/public.pem', response_class=Response)
async def get_public_pem(request: Request):
    signing_key = get_signing_key(request.app.state.jwks)
    data = signing_key.export_to_pem(private_key=False)
    return Response(content=data, media_type='application/x-pem-file')


@root_router.post('/transaction', response_model=AuthResponse, response_model_exclude_unset=True)
async def transaction(
    request: Request, auth_req: AuthRequest, ssl_client_cert: Optional[str] = Header(None),
):
    signing_key = get_signing_key(request.app.state.jwks)
    proof_ok = False
    entity_id = auth_req.keys.kid
    origins = auth_req.resources.origins
    logger.debug(f'entity_id: {entity_id}')
    logger.debug(f'origins: {origins}')

    if auth_req.keys.proof is Proof.MTLS:
        if ssl_client_cert is None:
            raise HTTPException(status_code=400, detail='no client certificate')
        client_cert = load_client_cert(ssl_client_cert)
        cc_fingerprint = client_cert.fingerprint(SHA256())
        logger.debug(f'client cert fingerprint: {str(cc_fingerprint)}')
        # Compare fingerprints
        mdq_certs = await xml_mdq_get(entity_id=entity_id, mdq_url=request.app.state.config.mdq_server)
        if mdq_certs is None:
            raise HTTPException(status_code=400, detail=f'{entity_id} not found')
        for item in mdq_certs:
            mdq_fingerprint = item.cert.fingerprint(SHA256())
            logger.debug(f'metadata {item.use} cert fingerprint: {str(mdq_fingerprint)}')
            if mdq_fingerprint == cc_fingerprint:
                proof_ok = True
                logger.info(f'{entity_id} metadata {item.use} cert fingerprint matches client cert fingerprint')
                break
    elif auth_req.keys.proof is Proof.HTTPSIGN:
        raise HTTPException(status_code=400, detail='httpsign is not implemented')
    elif auth_req.keys.proof is Proof.TEST and request.app.state.config.test_mode is True:
        logger.warning(f'TEST_MODE - access token will be returned with no proof')
        proof_ok = True
    else:
        raise HTTPException(status_code=400, detail='no supported proof method')

    if proof_ok:
        # Create access token
        claims = Claims(origins=origins, exp=request.app.state.config.expires_in, aud=request.app.state.config.audience)
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
        token.make_signed_token(signing_key)
        auth_response = AuthResponse(access_token=AccessToken(type='bearer', value=token.serialize()))
        logger.info(f'OK:{entity_id}:{request.app.state.config.audience}:{origins}')
        return auth_response

    return HTTPException(status_code=401, detail='permission denied')
