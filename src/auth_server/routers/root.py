# -*- coding: utf-8 -*-
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.models.gnap import GrantRequest, GrantResponse
from auth_server.models.jose import JWKS, JWKTypes
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

    auth_flow = request.app.auth_flow_class(
        request=request,
        grant_req=grant_req,
        tls_client_cert=tls_client_cert,
        detached_jws=detached_jws,
        config=config,
        signing_key=signing_key,
    )
    for flow_step in auth_flow.flow_steps:
        m = getattr(auth_flow, flow_step)
        logger.debug(f'step {flow_step} will be called')

        res = await m()
        if isinstance(res, GrantResponse):
            logger.info(f'step {flow_step} returned GrantResponse')
            logger.debug(res.dict(exclude_unset=True))
            return res

    raise HTTPException(status_code=401, detail='permission denied')
