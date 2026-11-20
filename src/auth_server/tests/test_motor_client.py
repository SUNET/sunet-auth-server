import asyncio
from os import environ
from pathlib import Path
from typing import Self
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from motor.motor_asyncio import AsyncIOMotorClient
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import load_config
from auth_server.db import client as db_client
from auth_server.db.client import clear_motor_client_cache, close_motor_clients, get_motor_client
from auth_server.testing import MongoTemporaryInstance

__author__ = "lundberg"


def _base_config(mongo_uri: str) -> dict[str, str]:
    datadir = Path(__file__).with_name("data")
    return {
        "testing": "true",
        "keystore_path": f"{datadir}/testing_jwks.json",
        "signing_key_id": "test-kid",
        "auth_token_issuer": "http://testserver",
        "auth_token_audience": "some_audience",
        "auth_flows": '["TestFlow"]',
        "mongo_uri": mongo_uri,
    }


class TestMotorClientCache(IsolatedAsyncioTestCase):
    async def asyncSetUp(self: Self) -> None:
        self.mongo_db = MongoTemporaryInstance.get_instance()
        environ.clear()
        environ.update(_base_config(self.mongo_db.uri))
        load_config.cache_clear()
        clear_motor_client_cache()

    async def asyncTearDown(self: Self) -> None:
        clear_motor_client_cache()
        environ.clear()
        load_config.cache_clear()

    async def test_same_loop_same_client(self: Self) -> None:
        first = await get_motor_client()
        second = await get_motor_client()
        assert first is not None
        assert first is second

    async def test_different_loops_different_clients(self: Self) -> None:
        first = await get_motor_client()

        def in_new_loop() -> object:
            return asyncio.run(get_motor_client())

        second = await asyncio.to_thread(in_new_loop)
        assert first is not None
        assert second is not None
        assert first is not second
        # the loop of the second client is closed, so it is pruned on the next call
        assert await get_motor_client() is first
        assert len(db_client._motor_clients) == 1

    async def test_no_mongo_uri(self: Self) -> None:
        environ.pop("mongo_uri")
        load_config.cache_clear()
        assert await get_motor_client() is None

    async def test_changed_uri_new_client(self: Self) -> None:
        first = await get_motor_client()
        environ["mongo_uri"] = "mongodb://localhost:1/other"
        load_config.cache_clear()
        second = await get_motor_client()
        assert second is not first
        assert await get_motor_client() is second
        assert len(db_client._motor_clients) == 1

    async def test_close_motor_clients(self: Self) -> None:
        client = await get_motor_client()
        assert client is not None
        with patch.object(AsyncIOMotorClient, "close") as mock_close:
            await close_motor_clients()
            mock_close.assert_called_once()
        assert len(db_client._motor_clients) == 0
        # idempotent, also when nothing is cached
        await close_motor_clients()
        await close_motor_clients()
        assert len(db_client._motor_clients) == 0

    async def test_close_failure_is_swallowed(self: Self) -> None:
        client = await get_motor_client()
        assert client is not None
        with patch.object(AsyncIOMotorClient, "close", side_effect=RuntimeError("Event loop is closed")):
            await close_motor_clients()
        assert len(db_client._motor_clients) == 0


class TestMotorClientApp(TestCase):
    def setUp(self: Self) -> None:
        self.mongo_db = MongoTemporaryInstance.get_instance()
        environ.clear()
        environ.update(_base_config(self.mongo_db.uri))
        load_config.cache_clear()
        clear_motor_client_cache()
        self.app = init_auth_server_api()

    def tearDown(self: Self) -> None:
        clear_motor_client_cache()
        environ.clear()
        load_config.cache_clear()

    def test_lifespan_shutdown_empties_cache(self: Self) -> None:
        with TestClient(self.app) as client:
            # with the context manager all requests share one portal and thus one event loop
            assert client.get("/status/healthy").json()["status"] == "STATUS_OK_"
            assert len(db_client._motor_clients) == 1
        assert len(db_client._motor_clients) == 0

    def test_lifespan_shutdown_calls_close(self: Self) -> None:
        with patch("auth_server.api.close_motor_clients") as mock_close, TestClient(self.app):
            pass
        mock_close.assert_called_once()

    def test_many_requests_do_not_grow_cache(self: Self) -> None:
        client = TestClient(self.app)  # no context manager: a new event loop for every request
        for _ in range(25):
            assert client.get("/status/healthy").json()["status"] == "STATUS_OK_"
        assert len(db_client._motor_clients) <= 2
