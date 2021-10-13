# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form
from starlette.responses import HTMLResponse

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequest, ContextRequestRoute
from auth_server.templating import TestableJinja2Templates

logger = logging.getLogger(__name__)

interaction_router = APIRouter(route_class=ContextRequestRoute, prefix='/interaction')
templates = TestableJinja2Templates(directory=str(Path(__file__).with_name('templates')))


@interaction_router.get('/redirect/{transaction_id}')
async def redirect(request: ContextRequest, transaction_id: str, config: AuthServerConfig = Depends(load_config)):
    pass


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
