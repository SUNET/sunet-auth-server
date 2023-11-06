# -*- coding: utf-8 -*-
__author__ = "lundberg"

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException
from loguru import logger
from starlette.responses import HTMLResponse, RedirectResponse, Response

from auth_server.config import load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import FlowState, TransactionState, get_transaction_state_db
from auth_server.models.gnap import FinishInteractionMethod
from auth_server.templating import TestableJinja2Templates
from auth_server.utils import get_interaction_hash, push_interaction_finish

interaction_router = APIRouter(route_class=ContextRequestRoute, prefix="/interaction")
templates = TestableJinja2Templates(directory=str(Path(__file__).with_name("templates")))


@interaction_router.get("/redirect/{transaction_id}", response_class=HTMLResponse)
async def redirect(request: ContextRequest, transaction_id: str, background_tasks: BackgroundTasks) -> Response:
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    transaction_state = await transaction_db.get_state_by_transaction_id(transaction_id)
    if transaction_state is None:
        raise HTTPException(status_code=404, detail="transaction not found")

    assert isinstance(transaction_state, TransactionState)  # please mypy

    if transaction_state.flow_state is not FlowState.PENDING:
        logger.error(f"transaction flow state is {transaction_state.flow_state}, should be {FlowState.PENDING}")
        raise HTTPException(status_code=400, detail="transaction is in the wrong state")

    # we only support saml2 for user authentication for now
    if not transaction_state.saml_assertion:
        redirect_url = request.url_for("authenticate", transaction_id=transaction_state.transaction_id)
        return RedirectResponse(redirect_url)

    return await finish_interaction(
        request=request, transaction_state=transaction_state, background_tasks=background_tasks
    )


@interaction_router.get("/code", response_class=HTMLResponse)
async def user_code_input(request: ContextRequest):
    return templates.TemplateResponse("user_code.jinja2", context={"request": request})


@interaction_router.post("/code", response_class=HTMLResponse)
async def user_code_finish(request: ContextRequest, user_code: Optional[str] = Form(...)) -> Response:
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    if user_code is None:
        # TODO: show error in template
        return templates.TemplateResponse("user_code.jinja2", context={"request": request})

    transaction_state = await transaction_db.get_state_by_user_code(user_code)
    if transaction_state is None:
        raise HTTPException(status_code=404, detail="transaction not found")

    # now that we have found the transaction state use the redirect endpoint to continue the user authentication
    redirect_url = request.url_for("redirect", transaction_id=transaction_state.transaction_id)
    return RedirectResponse(status_code=303, url=redirect_url)


async def finish_interaction(
    request: ContextRequest, transaction_state: TransactionState, background_tasks: BackgroundTasks
) -> Response:
    config = load_config()
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    # set transaction flow state to approved as interaction finished successfully
    transaction_state.flow_state = FlowState.APPROVED
    await transaction_db.save(state=transaction_state, expires_in=config.transaction_state_expires_in)

    # notify the client if any finish method was agreed upon
    if transaction_state.grant_request.interact and transaction_state.grant_request.interact.finish:
        assert transaction_state.interaction_reference  # please mypy
        assert transaction_state.grant_response.interact  # please mypy
        assert transaction_state.grant_response.interact.finish  # please mypy

        interact_ref = transaction_state.interaction_reference
        interaction_hash = get_interaction_hash(
            client_nonce=transaction_state.grant_request.interact.finish.nonce,
            as_nonce=transaction_state.grant_response.interact.finish,
            interact_ref=interact_ref,
            transaction_url=str(
                request.url_for("transaction"),
            ),
        )

        # redirect method
        if transaction_state.grant_request.interact.finish.method is FinishInteractionMethod.REDIRECT:
            redirect_url = f"{transaction_state.grant_request.interact.finish.uri}?hash={interaction_hash}&interact_ref={interact_ref}"
            return RedirectResponse(redirect_url)
        # push method
        elif transaction_state.grant_request.interact.finish.method is FinishInteractionMethod.PUSH:
            background_tasks.add_task(
                push_interaction_finish,
                url=transaction_state.grant_request.interact.finish.uri,
                interaction_hash=interaction_hash,
                interaction_reference=interact_ref,
            )
    return templates.TemplateResponse("interaction_finished.jinja2", context={"request": request})
