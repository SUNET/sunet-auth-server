__author__ = "lundberg"

import logging
from hmac import compare_digest
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.templating import Jinja2Templates

from auth_server.config import load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.db.transaction_state import FlowState, TransactionState, get_transaction_state_db
from auth_server.models.gnap import FinishInteractionMethod
from auth_server.utils import get_hex_uuid4, get_interaction_hash, push_interaction_finish

logger = logging.getLogger(__name__)

interaction_router = APIRouter(route_class=ContextRequestRoute, prefix="/interaction")
templates = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))

INTERACTION_SESSION_COOKIE_PREFIX = "interaction_session_"


def _interaction_session_cookie_name(transaction_id: str) -> str:
    # one cookie per transaction, so that starting a new interaction does not lock the browser out of an older one
    return f"{INTERACTION_SESSION_COOKIE_PREFIX}{transaction_id}"


@interaction_router.get("/redirect/{transaction_id}")
async def redirect(request: ContextRequest, transaction_id: str) -> Response:
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

    started_interaction = False
    if transaction_state.interaction_session_id is None:
        # the first browser to show up starts the interaction and gets bound to the transaction
        interaction_session_id = get_hex_uuid4()
        interaction_csrf_token = get_hex_uuid4()
        started_interaction = await transaction_db.start_interaction(
            transaction_id=transaction_state.transaction_id,
            interaction_session_id=interaction_session_id,
            interaction_csrf_token=interaction_csrf_token,
        )
        if started_interaction:
            transaction_state.interaction_session_id = interaction_session_id
            transaction_state.interaction_csrf_token = interaction_csrf_token
        else:
            # another request bound the transaction first, reload what it stored
            transaction_state = await transaction_db.get_state_by_transaction_id(transaction_id)
            if transaction_state is None:
                raise HTTPException(status_code=404, detail="transaction not found")

    if not started_interaction and not _interaction_session_matches(
        request=request, transaction_state=transaction_state
    ):
        logger.error(f"interaction session mismatch for transaction {transaction_state.transaction_id}")
        raise HTTPException(status_code=403, detail="the interaction was started in another browser")

    # we only support saml2 for user authentication for now
    if not transaction_state.saml_session_info:
        redirect_url = request.url_for("authenticate", transaction_id=transaction_state.transaction_id)
        response: Response = RedirectResponse(redirect_url, status_code=303)
    else:
        # the user is authenticated, ask them to approve the request before the transaction is approved
        response = templates.TemplateResponse(
            request=request,
            name="consent.jinja2",
            context={
                "request": request,
                "consent_url": request.url_for("consent", transaction_id=transaction_state.transaction_id),
                "csrf_token": transaction_state.interaction_csrf_token,
                "requested_access": transaction_state.requested_access,
                "requested_subject": _requested_subject_summary(transaction_state),
            },
        )

    if started_interaction:
        _set_interaction_session_cookie(request=request, response=response, transaction_state=transaction_state)
    return response


def _set_interaction_session_cookie(
    request: ContextRequest, response: Response, transaction_state: TransactionState
) -> None:
    assert transaction_state.interaction_session_id is not None  # please mypy
    config = load_config()
    response.set_cookie(
        key=_interaction_session_cookie_name(transaction_state.transaction_id),
        value=transaction_state.interaction_session_id,
        max_age=int(config.transaction_state_expires_in.total_seconds()),
        path=f"{config.application_root}/interaction",
        httponly=True,
        # lax is enough, and needed: the browser returns from the IdP through a cross site redirect
        samesite="lax",
        secure=request.url.scheme == "https",
    )


def _interaction_session_matches(request: ContextRequest, transaction_state: TransactionState) -> bool:
    """is this the browser that started the interaction?"""
    interaction_session_id = request.cookies.get(_interaction_session_cookie_name(transaction_state.transaction_id))
    if interaction_session_id is None or transaction_state.interaction_session_id is None:
        return False
    return compare_digest(interaction_session_id, transaction_state.interaction_session_id)


@interaction_router.post("/consent/{transaction_id}")
async def consent(
    request: ContextRequest,
    transaction_id: str,
    background_tasks: BackgroundTasks,
    csrf_token: str = Form(...),
    decision: str = Form(...),
) -> Response:
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

    if not transaction_state.saml_session_info:
        logger.error("consent given for a transaction with no authenticated user")
        raise HTTPException(status_code=400, detail="user is not authenticated")

    if not _interaction_session_matches(request=request, transaction_state=transaction_state):
        logger.error(f"interaction session mismatch in consent for transaction {transaction_state.transaction_id}")
        raise HTTPException(status_code=403, detail="the interaction was started in another browser")

    if transaction_state.interaction_csrf_token is None or not compare_digest(
        csrf_token, transaction_state.interaction_csrf_token
    ):
        logger.error("csrf token mismatch in consent request")
        raise HTTPException(status_code=403, detail="consent could not be verified")

    if decision != "approve":
        logger.info(f"user denied transaction {transaction_state.transaction_id}")
        transaction_state.flow_state = FlowState.DENIED
        finished_template = "interaction_denied.jinja2"
    else:
        logger.info(f"user approved transaction {transaction_state.transaction_id}")
        transaction_state.flow_state = FlowState.APPROVED
        finished_template = "interaction_finished.jinja2"

    return await finish_interaction(
        request=request,
        transaction_state=transaction_state,
        background_tasks=background_tasks,
        finished_template=finished_template,
    )


def _requested_subject_summary(transaction_state: TransactionState) -> list[str]:
    """what the client asked to learn about the user, as a list for the consent screen"""
    requested_subject = transaction_state.requested_subject
    summary: list[str] = []
    if requested_subject.sub_id_formats:
        summary.extend(sub_id_format.value for sub_id_format in requested_subject.sub_id_formats)
    if requested_subject.assertion_formats:
        summary.extend(assertion_format.value for assertion_format in requested_subject.assertion_formats)
    return summary


@interaction_router.get("/code")
async def user_code_input(request: ContextRequest) -> Response:
    return templates.TemplateResponse(request=request, name="user_code.jinja2", context={"request": request})


@interaction_router.post("/code")
async def user_code_finish(request: ContextRequest, user_code: str | None = Form(...)) -> Response:
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    if user_code is None:
        # TODO: show error in template
        return templates.TemplateResponse(request=request, name="user_code.jinja2", context={"request": request})

    # normalize user code
    # the AS MUST transform the input string remove invalid characters
    # the AS MUST treat user input as case-insensitive
    user_code = "".join(user_code.split()).lower()
    if not user_code.isalnum():
        # TODO: show error in template
        return templates.TemplateResponse(request=request, name="user_code.jinja2", context={"request": request})

    transaction_state = await transaction_db.get_state_by_user_code(user_code)
    if transaction_state is None:
        raise HTTPException(status_code=404, detail="transaction not found")

    # now that we have found the transaction state use the redirect endpoint to continue the user authentication
    redirect_url = request.url_for("redirect", transaction_id=transaction_state.transaction_id)
    return RedirectResponse(status_code=303, url=redirect_url)


async def finish_interaction(
    request: ContextRequest,
    transaction_state: TransactionState,
    background_tasks: BackgroundTasks,
    finished_template: str,
) -> RedirectResponse | HTMLResponse:
    config = load_config()
    transaction_db = await get_transaction_state_db()
    if transaction_db is None:
        # if there is no database available no requests should get here
        raise HTTPException(status_code=400, detail="interaction not supported")

    # the caller has set the flow state to the user's decision, persist it before notifying the client
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

        # TODO: The client instance's URI MUST be protected by HTTPS, be hosted on a
        #       server local to the RO's browser ("localhost"), or use an
        #       application-specific URI scheme that is loaded on the end user's
        #       device.

        # redirect method
        if transaction_state.grant_request.interact.finish.method is FinishInteractionMethod.REDIRECT:
            redirect_url = (
                f"{transaction_state.grant_request.interact.finish.uri}?"
                f"hash={interaction_hash}&interact_ref={interact_ref}"
            )
            return RedirectResponse(redirect_url, status_code=303)
        # push method
        elif transaction_state.grant_request.interact.finish.method is FinishInteractionMethod.PUSH:
            background_tasks.add_task(
                push_interaction_finish,
                url=transaction_state.grant_request.interact.finish.uri,
                interaction_hash=interaction_hash,
                interaction_reference=interact_ref,
            )
    return templates.TemplateResponse(request=request, name=finished_template, context={"request": request})
