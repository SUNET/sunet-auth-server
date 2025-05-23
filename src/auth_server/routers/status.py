import asyncio
from logging import getLogger

from fastapi import APIRouter
from pymongo.errors import ConnectionFailure

from auth_server.config import load_config
from auth_server.db.client import get_motor_client
from auth_server.models.status import Status, StatusResponse

__author__ = "lundberg"

logger = getLogger(__name__)
status_router = APIRouter(prefix="/status")


async def _mongodb_health_check() -> bool:
    config = load_config()
    if config.mongo_uri is None:
        # no mongodb configured
        return True

    client = await get_motor_client()
    assert client is not None  # please mypy
    try:
        await client.admin.command("ismaster")
        return True
    except ConnectionFailure as e:
        logger.error(f"mongodb not healthy: {e}")
        return False


@status_router.get("/healthy", response_model=StatusResponse, response_model_exclude_unset=True)
async def healthy() -> StatusResponse:
    checks = [_mongodb_health_check()]
    check_results = await asyncio.gather(*checks)
    if all(check_results):
        return StatusResponse(status=Status.OK)
    else:
        return StatusResponse(status=Status.FAIL)
