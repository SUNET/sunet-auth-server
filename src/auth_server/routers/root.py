# -*- coding: utf-8 -*-
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import TransactionState
from auth_server.flows import NextFlowException, StopTransactionException
from auth_server.models.gnap import ContinueRequest, GrantRequest, GrantResponse
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
    logger.debug(f'grant_req: {grant_req}')
    logger.debug(f'tls_client_cert: {tls_client_cert}')
    logger.debug(f'detached_jws: {detached_jws}')

    # Run configured auth flows
    for auth_flow in request.app.auth_flows:
        if auth_flow.get_version() != 1:
            logger.warning(f'not loading {auth_flow.get_name()} because it is version {auth_flow.version}')
            continue
        logger.debug(f'calling {auth_flow.get_name()}')

        # init a new flow state
        state = TransactionState(
            flow_name=auth_flow.get_name(),
            grant_request=grant_req.copy(deep=True),  # let every flow have their own copy of the grant request,
            tls_client_cert=tls_client_cert,
            jws_header=request.context.jws_header,
            detached_jws=detached_jws,
        )

        try:
            flow = auth_flow(request=request, config=config, signing_key=signing_key, state=state.to_dict())
            res = await flow.transaction()
        except NextFlowException as e:
            logger.info(f'flow {auth_flow.get_name()} stopped: {e.detail}')
            continue
        except StopTransactionException as e:
            logger.error(f'transaction stopped in flow {auth_flow.get_name()} with exception: {e.detail}')
            raise HTTPException(status_code=e.status_code, detail=e.detail)

        if isinstance(res, GrantResponse):
            logger.info(f'flow {auth_flow.get_name()} returned GrantResponse')
            logger.debug(res.dict(exclude_unset=True))
            return res

    raise HTTPException(status_code=401, detail='permission denied')


@root_router.post('/continue', response_model=GrantResponse, response_model_exclude_unset=True)
async def continue_transaction(
    request: ContextRequest,
    continue_req: ContinueRequest,
    tls_client_cert: Optional[str] = Header(None),
    detached_jws: Optional[str] = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
):
    logger.debug(f'continue_req: {continue_req}')
    logger.debug(f'tls_client_cert: {tls_client_cert}')
    logger.debug(f'detached_jws: {detached_jws}')
    pass
