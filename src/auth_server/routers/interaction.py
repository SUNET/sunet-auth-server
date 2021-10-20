# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException
from starlette.responses import HTMLResponse, RedirectResponse

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import TransactionState, get_transaction_state_db
from auth_server.models.gnap import FinishInteractionMethod
from auth_server.templating import TestableJinja2Templates
from auth_server.utils import get_interaction_hash, push_interaction_finish

logger = logging.getLogger(__name__)

interaction_router = APIRouter(route_class=ContextRequestRoute, prefix='/interaction')
templates = TestableJinja2Templates(directory=str(Path(__file__).with_name('templates')))


@interaction_router.get('/redirect/{transaction_id}')
async def redirect(request: ContextRequest, transaction_id: str, background_tasks: BackgroundTasks):
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=404, detail="Not found")

    transaction_state = await transaction_db.get_state_by_transaction_id(transaction_id)
    if transaction_state is None:
        raise HTTPException(status_code=404, detail="transaction not found")
    assert isinstance(transaction_state, TransactionState)  # please mypy

    # we only support saml2 for user authentication for now
    if not transaction_state.saml_assertion:
        # TODO: create saml auth request
        pass

    # notify the client if any finish method was agreed upon
    if transaction_state.finish_interaction:
        assert transaction_state.grant_response.interact  # please mypy
        assert transaction_state.grant_response.interact.finish  # please mypy
        assert transaction_state.interaction_reference  # please mypy

        interact_ref = transaction_state.interaction_reference
        interaction_hash = get_interaction_hash(
            client_nonce=transaction_state.finish_interaction.nonce,
            as_nonce=transaction_state.grant_response.interact.finish,
            interact_ref=interact_ref,
            transaction_url=request.url_for('transaction'),
        )
        if transaction_state.finish_interaction is FinishInteractionMethod.REDIRECT:
            redirect_url = f'{transaction_state.finish_interaction.uri}?hash={interaction_hash}&{interact_ref}'
            return RedirectResponse(redirect_url)
        elif transaction_state.finish_interaction is FinishInteractionMethod.PUSH:
            background_tasks.add_task(
                push_interaction_finish,
                url=transaction_state.grant_request.interact.finish.uri,
                interaction_hash=interaction_hash,
                interaction_reference=interact_ref,
            )
    return templates.TemplateResponse("interaction_finished.jinja2", context={'request': request})


@interaction_router.get('/code', response_class=HTMLResponse)
async def user_code_input(
    request: ContextRequest, config: AuthServerConfig = Depends(load_config),
):
    return templates.TemplateResponse("user_code.jinja2", context={'request': request})


@interaction_router.post('/code', response_class=HTMLResponse)
async def user_code_finish(
    request: ContextRequest, user_code: Optional[str] = Form(...), config: AuthServerConfig = Depends(load_config),
):
    return {'user_code': user_code}
