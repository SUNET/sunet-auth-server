# -*- coding: utf-8 -*-
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.flows import BaseAuthFlow
from auth_server.models.gnap import GrantRequest, GrantResponse
from auth_server.models.jose import JWKS, JWKTypes
from auth_server.utils import get_signing_key, import_class, load_jwks

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
    auth_flow_class = import_class(config.auth_flow_class)
    auth_flow: BaseAuthFlow = auth_flow_class(
        request=request,
        grant_req=grant_req,
        tls_client_cert=tls_client_cert,
        detached_jws=detached_jws,
        config=config,
        signing_key=signing_key,
    )

    await auth_flow.lookup_client()
    await auth_flow.lookup_client_key()
    await auth_flow.validate_proof()
    return await auth_flow.create_grant_response()
