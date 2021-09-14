# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form
from starlette.responses import HTMLResponse

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.templating import TestableJinja2Templates

logger = logging.getLogger(__name__)

interaction_router = APIRouter(route_class=ContextRequestRoute, prefix='/interaction')
templates = TestableJinja2Templates(directory="templates")


@interaction_router.get('/{transaction_id}')
async def interaction(request: ContextRequest, transaction_id: str, config: AuthServerConfig = Depends(load_config)):
    pass


@interaction_router.get('/{transaction_id}/short-code', response_class=HTMLResponse)
async def get_short_code(
    request: ContextRequest, transaction_id: str, config: AuthServerConfig = Depends(load_config),
):
    return templates.TemplateResponse(
        "short_code.jinja2", context={'request': request, 'transaction_id': transaction_id}
    )


@interaction_router.post('/{transaction_id}/short-code')
async def post_short_code(
    request: ContextRequest,
    transaction_id: str,
    short_code: Optional[str] = Form(...),
    config: AuthServerConfig = Depends(load_config),
):
    return {'transaction_id': transaction_id, 'short_code': short_code}
