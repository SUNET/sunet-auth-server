# -*- coding: utf-8 -*-
import logging

from fastapi import APIRouter

from auth_server.models.status import StatusResponse, Status

__author__ = 'lundberg'


logger = logging.getLogger(__name__)

status_router = APIRouter(prefix='/status')


@status_router.get('/healthy', response_model=StatusResponse, response_model_exclude_unset=True)
async def healthy():
    # TODO: Implement a real health check
    return StatusResponse(status=Status.OK)
