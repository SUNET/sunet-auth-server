# -*- coding: utf-8 -*-
__author__ = "lundberg"

import logging
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Query, Response
from saml2.metadata import entity_descriptor
from starlette.responses import HTMLResponse, RedirectResponse

from auth_server.config import load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import get_transaction_state_db
from auth_server.routers.interaction import interaction_router
from auth_server.saml2 import (
    SAML2SP,
    AuthnRequestRef,
    BadSAMLResponse,
    get_authn_request,
    get_redirect_url,
    get_saml2_sp,
    process_assertion,
)
from auth_server.templating import TestableJinja2Templates

logger = logging.getLogger(__name__)

saml2_router = APIRouter(route_class=ContextRequestRoute, prefix="/saml2")
templates = TestableJinja2Templates(directory=str(Path(__file__).with_name("templates")))


@saml2_router.get("/sp/authn/{transaction_id}", response_class=HTMLResponse)
async def authenticate(
    request: ContextRequest,
    transaction_id: Optional[str],
):
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
            url=saml2_sp.discovery_service_url, entity_id=saml2_sp.client.config.entityid, return_url=return_url
        )
        logger.debug(f"discovery service redirect url: {discovery_service_redirect_url}")
        return RedirectResponse(discovery_service_redirect_url, status_code=303)

    return await redirect_to_idp(saml2_sp=saml2_sp, authn_id=authn_id, idp_entity_id=idp)


@saml2_router.get("/sp/discovery-response", response_class=HTMLResponse)
async def discovery_service_response(
    target: Optional[str] = None, entity_id: Optional[str] = Query(default=None, alias="entityID")
):
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


async def redirect_to_idp(saml2_sp: SAML2SP, authn_id: AuthnRequestRef, idp_entity_id: str) -> Response:
    try:
        _found_idp = saml2_sp.client.metadata[idp_entity_id]
    except KeyError:
        logger.error(f"Unknown SAML2 idp: {idp_entity_id} not in metadata")
        raise HTTPException(status_code=400, detail="requested IdP not found in metadata")

    logger.info(f"creating authn request, idp {idp_entity_id} will be used")
    authn_request = await get_authn_request(
        relay_state="",
        authn_id=authn_id,
        selected_idp=idp_entity_id,
        force_authn=True,
        sign_alg=saml2_sp.authn_sign_alg,
        digest_alg=saml2_sp.authn_digest_alg,
    )

    idp_redirect_url = await get_redirect_url(authn_request)
    logger.info("redirecting user to the IdP after discovery service response")
    logger.debug(f"_idp_redirect_url: {idp_redirect_url}")
    return RedirectResponse(idp_redirect_url, status_code=303)


@saml2_router.post("/sp/saml2-acs", response_class=HTMLResponse)
async def assertion_consumer_service(request: ContextRequest, saml_response: str = Form(alias="SAMLResponse")):
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    try:
        assertion_data = await process_assertion(saml_response=saml_response)
    except BadSAMLResponse as e:
        logger.exception(f"{e}")
        raise HTTPException(status_code=400, detail=f"Bad SAML response: {e}")

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

    transaction_state.saml_assertion = assertion_data.session_info
    await transaction_db.save(transaction_state, expires_in=config.transaction_state_expires_in)
    logger.debug(f"saml_assertion added to transaction state with id: {transaction_id}")

    finish_interaction_url = request.url_for("redirect", transaction_id=transaction_id)
    logger.info("saml authentication done, redirecting user to finish interaction")
    logger.debug(f"redirecting to: {finish_interaction_url}")
    return RedirectResponse(finish_interaction_url, status_code=303)


@saml2_router.get("/sp/metadata", response_class=Response, responses={200: {"content": {"text/xml": {}}}})
async def metadata():
    saml2_sp = await get_saml2_sp()
    if not saml2_sp:
        raise HTTPException(status_code=400, detail="SAML SP not configured")
    data = entity_descriptor(saml2_sp.client.config).to_string()
    return Response(content=data, media_type="text/xml")
