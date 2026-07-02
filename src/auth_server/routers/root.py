import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header
from jwcrypto.jwk import JWK, JWKSet
from starlette.responses import Response

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import FlowState, TransactionState, get_transaction_state_db
from auth_server.errors import GNAPErrorException
from auth_server.flows import (
    SUPPORTED_FINISH_METHODS,
    SUPPORTED_KEY_PROOFS,
    SUPPORTED_START_METHODS,
    NextFlowException,
    StopTransactionException,
)
from auth_server.models.gnap import (
    ContinueAccessToken,
    ContinueRequest,
    ErrorCode,
    GNAPServiceDiscovery,
    GrantRequest,
    GrantResponse,
    SubjectAssertionFormat,
)
from auth_server.models.jose import ECJWK, JWKS, RSAJWK, SymmetricJWK
from auth_server.utils import get_hex_uuid4, get_signing_key, load_jwks

__author__ = "lundberg"

logger = logging.getLogger(__name__)

root_router = APIRouter(route_class=ContextRequestRoute, prefix="")


@root_router.get("/.well-known/jwks.json", response_model=JWKS, response_model_exclude_unset=True)
async def get_jwks(jwks: JWKSet = Depends(load_jwks)) -> dict:
    jwks = jwks.export(private_keys=False, as_dict=True)
    return jwks


@root_router.get(
    "/.well-known/jwk.json", response_model=ECJWK | RSAJWK | SymmetricJWK, response_model_exclude_unset=True
)
async def get_jwk(signing_key: JWK = Depends(get_signing_key)) -> dict:
    return signing_key.export(private_key=False, as_dict=True)


@root_router.get("/.well-known/public.pem", responses={200: {"content": {"application/x-pem-file": {}}}})
async def get_public_pem(signing_key: JWK = Depends(get_signing_key)) -> Response:
    data = signing_key.export_to_pem(private_key=False)
    return Response(content=data, media_type="application/x-pem-file")


@root_router.options("/transaction", response_model=GNAPServiceDiscovery, response_model_exclude_none=True)
async def transaction_discovery(request: ContextRequest) -> GNAPServiceDiscovery:
    return GNAPServiceDiscovery(
        grant_request_endpoint=str(request.url_for("transaction")),
        interaction_start_modes_supported=SUPPORTED_START_METHODS,
        interaction_finish_methods_supported=SUPPORTED_FINISH_METHODS,
        key_proofs_supported=SUPPORTED_KEY_PROOFS,
        assertion_formats_supported=[SubjectAssertionFormat.SAML2],
        key_rotation_supported=False,
    )


@root_router.post("/transaction", response_model=GrantResponse, response_model_exclude_none=True)
async def transaction(
    request: ContextRequest,
    grant_req: GrantRequest,
    response: Response,
    client_cert: str | None = Header(None),
    detached_jws: str | None = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
) -> GrantResponse:
    # RFC 9635 requires Cache-Control: no-store on all grant responses
    response.headers["Cache-Control"] = "no-store"

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
            raise GNAPErrorException(status_code=e.status_code, error_code=e.error_code, description=e.detail)

        if isinstance(res, GrantResponse):
            logger.info(f"flow {auth_flow_name} returned GrantResponse")
            logger.debug(res.dict(exclude_none=True))
            return res

    raise GNAPErrorException(status_code=401, error_code=ErrorCode.REQUEST_DENIED, description="permission denied")


async def _load_continuation_doc(
    continue_req: ContinueRequest | None,
    continue_reference: str | None,
    authorization: str | None,
) -> Mapping[str, Any]:
    if authorization is None or not authorization.startswith("GNAP "):
        raise GNAPErrorException(
            status_code=401, error_code=ErrorCode.INVALID_CONTINUATION, description="missing continuation access token"
        )

    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no clients should try this endpoint
        raise GNAPErrorException(
            status_code=400, error_code=ErrorCode.INVALID_REQUEST, description="continuation not supported"
        )

    # load saved transaction state
    if continue_req is not None and continue_req.interact_ref is not None:
        transaction_doc = await transaction_db.get_document_by_interaction_reference(
            interaction_reference=continue_req.interact_ref
        )
    elif continue_reference is not None:
        transaction_doc = await transaction_db.get_document_by_continue_reference(continue_reference=continue_reference)
    else:
        transaction_doc = await transaction_db.get_document_by_continue_access_token(
            continue_access_token=authorization.removeprefix("GNAP ")
        )

    if transaction_doc is None:
        raise GNAPErrorException(
            status_code=404, error_code=ErrorCode.INVALID_CONTINUATION, description="transaction not found"
        )

    if authorization != f"GNAP {transaction_doc.get('continue_access_token')}":
        raise GNAPErrorException(
            status_code=401, error_code=ErrorCode.INVALID_CONTINUATION, description="permission denied"
        )

    return transaction_doc


# TODO: implement PATCH (modify transaction) for continue
@root_router.post("/continue/{continue_reference}", response_model=GrantResponse, response_model_exclude_none=True)
@root_router.post("/continue", response_model=GrantResponse, response_model_exclude_none=True)
async def continue_transaction(
    request: ContextRequest,
    response: Response,
    continue_req: ContinueRequest | None = None,
    continue_reference: str | None = None,
    client_cert: str | None = Header(None),
    detached_jws: str | None = Header(None),
    authorization: str | None = Header(None),  # TODO: should not really be optional?
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
) -> GrantResponse:
    # RFC 9635 requires Cache-Control: no-store on all grant responses
    response.headers["Cache-Control"] = "no-store"

    logger.debug(f"continue_req: {continue_req}")
    logger.debug(f"client_cert: {client_cert}")
    logger.debug(f"detached_jws: {detached_jws}")
    logger.debug(f"authorization: {authorization}")

    request.context.client_cert = client_cert
    request.context.detached_jws = detached_jws

    transaction_doc = await _load_continuation_doc(
        continue_req=continue_req, continue_reference=continue_reference, authorization=authorization
    )

    if continue_req is None:
        continue_req = ContinueRequest()

    transaction_state = TransactionState(**transaction_doc)
    logger.debug(f"transaction_state loaded: {transaction_state}")

    # initialize the flow that handled the original grant request
    auth_flow_name = transaction_state.flow_name
    auth_flow = request.app.auth_flows.get(auth_flow_name)
    if not auth_flow:
        raise GNAPErrorException(
            status_code=400, error_code=ErrorCode.INVALID_REQUEST, description="requested flow not loaded"
        )
    flow = auth_flow(request=request, config=config, signing_key=signing_key, state=dict(**transaction_doc))

    if transaction_state.flow_state is FlowState.FINALIZED:
        logger.debug(f"transaction state: {transaction_state.flow_state}. Grant is finalized, can not continue.")
        raise GNAPErrorException(
            status_code=401,
            error_code=ErrorCode.INVALID_CONTINUATION,
            description="grant is finalized and can not be continued",
        )

    if transaction_state.flow_state != FlowState.APPROVED:
        logger.debug(f"transaction state: {transaction_state.flow_state}. Can not continue yet.")
        # every continuation request must be signed with the same key as the grant request (RFC 9635 7.2)
        try:
            await flow.validate_continuation_proof(continue_request=continue_req)
        except (NextFlowException, StopTransactionException) as e:
            raise GNAPErrorException(
                status_code=e.status_code, error_code=ErrorCode.INVALID_CONTINUATION, description=e.detail
            )
        # rotate the continuation access token (RFC 9635 5.)
        flow.state.continue_access_token = get_hex_uuid4()
        assert flow.state.grant_response.continue_ is not None  # please mypy
        flow.state.grant_response.continue_.access_token = ContinueAccessToken(value=flow.state.continue_access_token)
        transaction_db = await get_transaction_state_db()
        assert transaction_db is not None  # already checked in _load_continuation_doc
        # rotation must not extend the transaction lifetime - pass a zero delta so expires_at is left as-is
        # (save() adds expires_in to the existing expires_at; that additive behaviour is relied on by the
        # initial-save callers, so it is not changed here)
        await transaction_db.save(flow.state, expires_in=timedelta(0))
        return flow.state.grant_response

    logger.debug(f"transaction state: {transaction_state.flow_state}. Continuing flow")
    # continue the transaction
    try:
        res = await flow.continue_transaction(continue_request=continue_req)
    except (NextFlowException, StopTransactionException) as e:  # there is no next flow when continuing
        logger.error(f"transaction stopped in flow {auth_flow_name} with exception: {e.detail}")
        raise GNAPErrorException(
            status_code=e.status_code,
            error_code=getattr(e, "error_code", ErrorCode.INVALID_REQUEST),
            description=e.detail,
        )

    if isinstance(res, GrantResponse):
        logger.info(f"flow {auth_flow_name} returned GrantResponse")
        logger.debug(res.dict(exclude_none=True))
        return res

    raise GNAPErrorException(status_code=401, error_code=ErrorCode.REQUEST_DENIED, description="permission denied")


@root_router.delete("/continue/{continue_reference}", status_code=204)
@root_router.delete("/continue", status_code=204)
async def delete_transaction(
    request: ContextRequest,
    continue_reference: str | None = None,
    client_cert: str | None = Header(None),
    detached_jws: str | None = Header(None),
    authorization: str | None = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
) -> Response:
    request.context.client_cert = client_cert
    request.context.detached_jws = detached_jws

    transaction_doc = await _load_continuation_doc(
        continue_req=None, continue_reference=continue_reference, authorization=authorization
    )
    transaction_state = TransactionState(**transaction_doc)

    auth_flow = request.app.auth_flows.get(transaction_state.flow_name)
    if not auth_flow:
        raise GNAPErrorException(
            status_code=400, error_code=ErrorCode.INVALID_REQUEST, description="requested flow not loaded"
        )
    flow = auth_flow(request=request, config=config, signing_key=signing_key, state=dict(**transaction_doc))
    try:
        await flow.validate_continuation_proof(continue_request=ContinueRequest())
    except (NextFlowException, StopTransactionException) as e:
        raise GNAPErrorException(
            status_code=e.status_code, error_code=ErrorCode.INVALID_CONTINUATION, description=e.detail
        )

    transaction_db = await get_transaction_state_db()
    assert transaction_db is not None  # already checked in _load_continuation_doc
    await transaction_db.remove_state(transaction_id=transaction_state.transaction_id)
    logger.info(f"transaction {transaction_state.transaction_id} revoked by client")
    return Response(status_code=204)


@root_router.delete("/token/{token_reference}", status_code=204, name="token_management")
async def revoke_token(
    request: ContextRequest,
    token_reference: str,
    client_cert: str | None = Header(None),
    detached_jws: str | None = Header(None),
    authorization: str | None = Header(None),
    config: AuthServerConfig = Depends(load_config),
    signing_key: JWK = Depends(get_signing_key),
) -> Response:
    request.context.client_cert = client_cert
    request.context.detached_jws = detached_jws

    if authorization is None:
        raise GNAPErrorException(
            status_code=401, error_code=ErrorCode.INVALID_REQUEST, description="missing token management access token"
        )

    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        raise GNAPErrorException(
            status_code=400, error_code=ErrorCode.INVALID_REQUEST, description="token management not supported"
        )

    transaction_doc = await transaction_db.get_document_by_token_reference(token_reference=token_reference)
    if transaction_doc is None:
        raise GNAPErrorException(status_code=404, error_code=ErrorCode.INVALID_REQUEST, description="token not found")

    transaction_state = TransactionState(**transaction_doc)
    if authorization != f"GNAP {transaction_state.token_management_access_token}":
        raise GNAPErrorException(status_code=401, error_code=ErrorCode.INVALID_REQUEST, description="permission denied")

    auth_flow = request.app.auth_flows.get(transaction_state.flow_name)
    if not auth_flow:
        raise GNAPErrorException(
            status_code=400, error_code=ErrorCode.INVALID_REQUEST, description="requested flow not loaded"
        )
    flow = auth_flow(request=request, config=config, signing_key=signing_key, state=dict(**transaction_doc))
    try:
        await flow.validate_continuation_proof(
            continue_request=ContinueRequest(), access_token=transaction_state.token_management_access_token
        )
    except (NextFlowException, StopTransactionException) as e:
        raise GNAPErrorException(status_code=e.status_code, error_code=ErrorCode.INVALID_REQUEST, description=e.detail)

    # NOTE: the JWT stays technically valid until exp as resource servers validate it offline;
    # revocation removes the AS-side state (and with it token management/continuation)
    await transaction_db.remove_state(transaction_id=transaction_state.transaction_id)
    logger.info(f"access token for transaction {transaction_state.transaction_id} revoked by client")
    return Response(status_code=204)


@root_router.post("/token/{token_reference}", name="token_rotation")
async def rotate_token(token_reference: str) -> Response:
    # access token rotation is not supported (RFC 9635 6.1)
    raise GNAPErrorException(
        status_code=400, error_code=ErrorCode.INVALID_ROTATION, description="access token rotation is not supported"
    )
