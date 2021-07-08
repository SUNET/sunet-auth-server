# -*- coding: utf-8 -*-
import asyncio
import logging

from fastapi import APIRouter
from pymongo.errors import ConnectionFailure

from auth_server.config import load_config
from auth_server.db.client import get_mongodb_client
from auth_server.models.status import Status, StatusResponse

__author__ = 'lundberg'


logger = logging.getLogger(__name__)

status_router = APIRouter(prefix='/status')


async def _mongodb_health_check():
    config = load_config()
    if config.mongo_uri is None:
        # no mongodb configured
        return True

    client = await get_mongodb_client()
    try:
        await client.admin.command('ismaster')
        return True
    except ConnectionFailure as e:
        logging.error(f'mongodb not healthy: {e}')
        return False


@status_router.get('/healthy', response_model=StatusResponse, response_model_exclude_unset=True)
async def healthy():
    checks = [_mongodb_health_check()]
    check_results = await asyncio.gather(*checks)
    if all(check_results):
        return StatusResponse(status=Status.OK)
    else:
        return StatusResponse(status=Status.FAIL)
