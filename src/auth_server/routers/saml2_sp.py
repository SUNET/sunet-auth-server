__author__ = "lundberg"

import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Query, Response
from saml2.metadata import entity_descriptor
from saml2.response import StatusError
from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates

from auth_server.config import load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import get_transaction_state_db
from auth_server.saml2 import (
    SAML2SP,
    AuthnRequestRef,
    BadSAMLResponse,
    get_authn_request,
    get_redirect_url,
    get_saml2_sp,
    process_assertion,
)

logger = logging.getLogger(__name__)

saml2_router = APIRouter(route_class=ContextRequestRoute, prefix="/saml2")
templates = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))


@saml2_router.get("/sp/authn/{transaction_id}")
async def authenticate(
    request: ContextRequest,
    transaction_id: str,
) -> RedirectResponse:
    saml2_sp = await get_saml2_sp()
    if saml2_sp is None:
        # there is no pysaml2 config or any database available
        raise HTTPException(status_code=400, detail="SAML authentication not configured")

    # use single IdP config option if set
    idp = saml2_sp.single_idp

    # create a unique authn req reference to map this request to the current transaction
    authn_id = AuthnRequestRef(str(uuid.uuid4()))
    saml2_sp.authn_req_cache[authn_id] = transaction_id
    logger.debug(f"Stored authn request[{authn_id}]: {saml2_sp.authn_req_cache[authn_id]}")

    if idp is None:
        # No IdP requested, send user to discovery service
        if saml2_sp.discovery_service_url is None:
            logger.error("No IdP requested and no discovery service configured")
            raise HTTPException(status_code=400, detail="no IdP requested")
        return_url = f'{request.url_for("discovery_service_response")}/?target={authn_id}'
        logger.debug(f"discovery service return_url: {return_url}")
        discovery_service_redirect_url = saml2_sp.client.create_discovery_service_request(
            url=str(saml2_sp.discovery_service_url), entity_id=saml2_sp.client.config.entityid, return_url=return_url
        )
        logger.debug(f"discovery service redirect url: {discovery_service_redirect_url}")
        return RedirectResponse(discovery_service_redirect_url, status_code=303)

    return await redirect_to_idp(saml2_sp=saml2_sp, authn_id=authn_id, idp_entity_id=idp)


@saml2_router.get("/sp/discovery-response")
async def discovery_service_response(
    target: str | None = None, entity_id: str | None = Query(default=None, alias="entityID")
) -> Response:
    saml2_sp = await get_saml2_sp()
    if saml2_sp is None:
        # there is no pysaml2 config or any database available
        raise HTTPException(status_code=400, detail="SAML authentication not configured")

    if target is None or entity_id is None:
        logger.error(f"Bad discovery service response. target: {target}, entity id: {entity_id}")
        raise HTTPException(status_code=400, detail="bad discovery service response")

    logger.debug(f"discovery response target: {target}, entityID: {entity_id}")

    authn_id = AuthnRequestRef(target)
    # check if this response is from an ongoing authentication request
    if authn_id not in saml2_sp.authn_req_cache:
        logger.error(f"Could not find target: {target}")
        raise HTTPException(status_code=400, detail="authentication request target not found")

    # discovery response seems to check out, send user to the IdP
    return await redirect_to_idp(saml2_sp=saml2_sp, authn_id=authn_id, idp_entity_id=entity_id)


async def redirect_to_idp(saml2_sp: SAML2SP, authn_id: AuthnRequestRef, idp_entity_id: str) -> RedirectResponse:
    try:
        _found_idp = saml2_sp.client.metadata[idp_entity_id]
    except KeyError:
        logger.error(f"Unknown SAML2 idp: {idp_entity_id} not in metadata")
        raise HTTPException(status_code=400, detail="requested IdP not found in metadata")

    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        logger.error("No transaction db found")
        raise HTTPException(status_code=400, detail="SAML authentication misconfigured")

    # get any requested authentication context from subject request
    required_loa = None
    transaction_id = saml2_sp.authn_req_cache[authn_id]
    assert isinstance(transaction_id, str)  # please mypy
    transaction_state = await transaction_db.get_state_by_transaction_id(transaction_id=transaction_id)
    if transaction_state is not None and transaction_state.requested_subject.authentication_context is not None:
        required_loa = transaction_state.requested_subject.authentication_context

    logger.info(f"creating authn request, idp {idp_entity_id} will be used")
    authn_request = await get_authn_request(
        relay_state="",
        authn_id=authn_id,
        selected_idp=idp_entity_id,
        force_authn=True,
        sign_alg=saml2_sp.authn_sign_alg,
        digest_alg=saml2_sp.authn_digest_alg,
        required_loa=required_loa,
    )

    if not authn_request:
        raise HTTPException(status_code=400, detail="Could not create authn request")

    idp_redirect_url = await get_redirect_url(authn_request)
    logger.info("redirecting user to the IdP after discovery service response")
    logger.debug(f"_idp_redirect_url: {idp_redirect_url}")
    return RedirectResponse(idp_redirect_url, status_code=303)


@saml2_router.post("/sp/saml2-acs")
async def assertion_consumer_service(
    request: ContextRequest, saml_response: str = Form(alias="SAMLResponse")
) -> RedirectResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    try:
        assertion_data = await process_assertion(saml_response=saml_response)
    except BadSAMLResponse as e:
        logger.exception(f"{e}")
        raise HTTPException(status_code=400, detail=f"Bad SAML response: {e}")
    except StatusError as e:
        logger.error(f"{e}")
        raise HTTPException(status_code=401, detail=f"SAML Status Error: {e}")

    config = load_config()
    saml2_sp = await get_saml2_sp()
    if not assertion_data or not saml2_sp:
        raise HTTPException(status_code=400, detail="SAML authentication not configured")

    logger.debug(f"Auth response:\n{assertion_data}\n\n")
    if (transaction_id := saml2_sp.authn_req_cache.get(assertion_data.authn_req_ref)) is None:
        logger.error(f"Could not find authn req ref: {assertion_data.authn_req_ref}")
        raise HTTPException(status_code=400, detail="authentication request not found")

    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    transaction_state = await transaction_db.get_state_by_transaction_id(transaction_id)
    if transaction_state is None:
        logger.error("transaction state not found")
        logger.debug(f"transaction_id: {transaction_id}")
        raise HTTPException(status_code=404, detail="transaction not found")

    if transaction_state.requested_subject.authentication_context is not None:
        for authn_info in assertion_data.session_info.authn_info:
            if authn_info.authn_class in transaction_state.requested_subject.authentication_context:
                break
        else:
            logger.error("authentication context mismatch: IdP did not assert any acceptable authentication context")
            logger.error(f"Requested: {transaction_state.requested_subject.authentication_context}")
            logger.error(f"Asserted: {assertion_data.session_info.authn_info}")
            raise HTTPException(status_code=401, detail="authentication context mismatch")

    transaction_state.saml_session_info = assertion_data.session_info
    await transaction_db.save(transaction_state, expires_in=config.transaction_state_expires_in)
    logger.debug(f"saml_assertion added to transaction state with id: {transaction_id}")

    finish_interaction_url = request.url_for("redirect", transaction_id=transaction_id)
    logger.info("saml authentication done, redirecting user to finish interaction")
    logger.debug(f"redirecting to: {finish_interaction_url}")
    return RedirectResponse(finish_interaction_url, status_code=303)


@saml2_router.get("/sp/metadata", responses={200: {"content": {"text/xml": {}}}})
async def metadata() -> Response:
    saml2_sp = await get_saml2_sp()
    if not saml2_sp:
        raise HTTPException(status_code=400, detail="SAML SP not configured")
    data = entity_descriptor(saml2_sp.client.config).to_string()
    return Response(content=data, media_type="text/xml")
