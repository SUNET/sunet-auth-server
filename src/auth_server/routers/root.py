# -*- coding: utf-8 -*-
import logging
from typing import Optional, Union

from fastapi import APIRouter, Depends, Header, HTTPException
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import FlowState, TransactionState, get_transaction_state_db
from auth_server.flows import NextFlowException, StopTransactionException
from auth_server.models.gnap import ContinueRequest, GrantRequest, GrantResponse
from auth_server.models.jose import ECJWK, JWKS, RSAJWK, SymmetricJWK
from auth_server.utils import get_signing_key, load_jwks

__author__ = "lundberg"

logger = logging.getLogger(__name__)

root_router = APIRouter(route_class=ContextRequestRoute, prefix="")


@root_router.get("/.well-known/jwks.json", response_model=JWKS, response_model_exclude_unset=True)
async def get_jwks(jwks: JWKSet = Depends(load_jwks)):
    jwks = jwks.export(private_keys=False, as_dict=True)
    return jwks


@root_router.get(
    "/.well-known/jwk.json", response_model=Union[ECJWK, RSAJWK, SymmetricJWK], response_model_exclude_unset=True
)
async def get_jwk(signing_key: JWK = Depends(get_signing_key)):
    return signing_key.export(private_key=False, as_dict=True)


@root_router.get(
    "/.well-known/public.pem", response_class=Response, responses={200: {"content": {"application/x-pem-file": {}}}}
)
async def get_public_pem(signing_key: JWK = Depends(get_signing_key)):
    data = signing_key.export_to_pem(private_key=False)
    return Response(content=data, media_type="application/x-pem-file")


# TODO implement OPTIONS (discovery)
@root_router.post("/transaction", response_model=GrantResponse, response_model_exclude_none=True)
async def transaction(
    request: ContextRequest,
    grant_req: GrantRequest,
    client_cert: Optional[str] = Header(None),
    detached_jws: Optional[str] = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
):
    logger.debug(f"grant_req: {grant_req}")
    logger.debug(f"client_cert: {client_cert}")
    logger.debug(f"detached_jws: {detached_jws}")

    request.context.client_cert = client_cert
    request.context.detached_jws = detached_jws

    # Run configured auth flows
    for auth_flow_name, auth_flow in request.app.auth_flows.items():
        if auth_flow.get_version() != 1:
            logger.warning(f"not loading {auth_flow_name} because it is version {auth_flow.version}")
            continue
        logger.debug(f"calling {auth_flow_name}")

        # init a new transaction state
        state = TransactionState(
            flow_name=auth_flow_name,
            grant_request=grant_req.model_copy(deep=True),  # let every flow have their own copy of the grant request,
        )

        flow = auth_flow(request=request, config=config, signing_key=signing_key, state=state.to_dict())
        try:
            res = await flow.transaction()
        except NextFlowException as e:
            logger.info(f"flow {auth_flow_name} stopped: {e.detail}")
            continue
        except StopTransactionException as e:
            logger.error(f"transaction stopped in flow {auth_flow_name} with exception: {e.detail}")
            raise HTTPException(status_code=e.status_code, detail=e.detail)

        if isinstance(res, GrantResponse):
            logger.info(f"flow {auth_flow_name} returned GrantResponse")
            logger.debug(res.dict(exclude_none=True))
            # TODO: The AS MUST include the HTTP Cache-Control response header field
            #       [RFC9111] with a value set to "no-store".
            return res

    raise HTTPException(status_code=401, detail="permission denied")


# TODO: implement DELETE (revoke transaction) and PATCH (modify transaction) for continue
@root_router.post("/continue/{continue_reference}", response_model=GrantResponse, response_model_exclude_none=True)
@root_router.post("/continue", response_model=GrantResponse, response_model_exclude_none=True)
async def continue_transaction(
    request: ContextRequest,
    continue_req: Optional[ContinueRequest] = None,
    continue_reference: Optional[str] = None,
    client_cert: Optional[str] = Header(None),
    detached_jws: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),  # TODO: should not really be optional?
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
):
    logger.debug(f"continue_req: {continue_req}")
    logger.debug(f"client_cert: {client_cert}")
    logger.debug(f"detached_jws: {detached_jws}")
    logger.debug(f"authorization: {authorization}")

    request.context.client_cert = client_cert
    request.context.detached_jws = detached_jws

    if authorization is None:
        raise HTTPException(status_code=401, detail="permission denied")

    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no clients should try this endpoint
        raise HTTPException(status_code=400, detail="continuation not supported")

    # load saved transaction state
    if continue_req is not None and continue_req.interact_ref is not None:
        transaction_doc = await transaction_db.get_document_by_interaction_reference(
            interaction_reference=continue_req.interact_ref
        )
    elif continue_reference is not None:
        transaction_doc = await transaction_db.get_document_by_continue_reference(continue_reference=continue_reference)
    else:
        raise HTTPException(status_code=400, detail="reference for transaction to continue is missing")

    if transaction_doc is None:
        raise HTTPException(status_code=404, detail="transaction not found")

    transaction_state = TransactionState(**transaction_doc)
    logger.debug(f"transaction_state loaded: {transaction_state}")

    # check continue access token
    if authorization != f"GNAP {transaction_state.continue_access_token}":
        raise HTTPException(status_code=401, detail="permission denied")

    # TODO: Need to verify that continuation responses are handled correctly
    # Do not return transaction reference again
    # Change continuation access token for next request
    # More?

    # return continue response again if interaction is not completed or interaction reference is not used
    if transaction_state.flow_state != FlowState.APPROVED:
        logger.debug(f"transaction state: {transaction_state.flow_state}. Can not continue yet.")
        # TODO: update expires_in, auth token and return error message to clients not waiting long enough
        return transaction_state.grant_response

    logger.debug(f"transaction state: {transaction_state.flow_state}. Continuing flow")
    # initialize flow to continue
    auth_flow_name = transaction_state.flow_name
    auth_flow = request.app.auth_flows.get(auth_flow_name)
    if not auth_flow:
        raise HTTPException(status_code=400, detail="requested flow not loaded")
    # update transaction_state with the clients current authentication as the authentication have to match
    # the transaction requests key that should be continued
    updated_transaction_doc = dict(**transaction_doc)
    flow = auth_flow(request=request, config=config, signing_key=signing_key, state=updated_transaction_doc)

    # continue the transaction
    try:
        res = await flow.continue_transaction(continue_request=continue_req)
    except (NextFlowException, StopTransactionException) as e:  # there is no next flow when continuing
        logger.error(f"transaction stopped in flow {auth_flow_name} with exception: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    if isinstance(res, GrantResponse):
        logger.info(f"flow {auth_flow_name} returned GrantResponse")
        logger.debug(res.dict(exclude_none=True))
        return res

    raise HTTPException(status_code=401, detail="permission denied")


# TODO: implement token management end point
