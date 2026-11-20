from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any, Self
from unittest import IsolatedAsyncioTestCase, mock
from unittest.mock import AsyncMock

import aiohttp

from auth_server.mdq import MDQData, xml_mdq_get
from auth_server.tests.test_app import MockResponse
from auth_server.tls_fed_auth import get_remote_metadata
from auth_server.utils import push_interaction_finish

__author__ = "lundberg"

TIMEOUT = timedelta(seconds=10)

_orig_close = aiohttp.ClientSession.close
_orig_init = aiohttp.ClientSession.__init__


@contextmanager
def patched_session(method: str, **kwargs: Any) -> Iterator[tuple[AsyncMock, AsyncMock, list[dict[str, Any]]]]:
    """Patch ClientSession.<method> and count close() calls; capture __init__ kwargs."""
    init_kwargs: list[dict[str, Any]] = []

    def _init(self: aiohttp.ClientSession, *args: Any, **kw: Any) -> None:
        init_kwargs.append(kw)
        _orig_init(self, *args, **kw)

    close_mock = AsyncMock(side_effect=lambda: None)
    with (
        mock.patch.object(aiohttp.ClientSession, method, new_callable=AsyncMock, **kwargs) as req_mock,
        mock.patch.object(aiohttp.ClientSession, "close", close_mock),
        mock.patch.object(aiohttp.ClientSession, "__init__", _init),
    ):
        yield req_mock, close_mock, init_kwargs


FAILURES: list[tuple[str, dict[str, Any]]] = [
    ("connection_error", {"side_effect": aiohttp.ClientConnectionError()}),
    ("timeout", {"side_effect": TimeoutError()}),
    ("status_500", {"return_value": MockResponse(status_code=500)}),
]


class TestHttpClients(IsolatedAsyncioTestCase):
    async def _check_failures(self: Self, method: str, call: Callable[[], Any], expected: object) -> None:
        for name, kwargs in FAILURES:
            with self.subTest(failure=name), patched_session(method, **kwargs) as (_, close_mock, init_kwargs):
                result = await call()
                assert result == expected
                assert close_mock.await_count == 1
                assert init_kwargs[0]["timeout"].total == 10.0

    async def _check_success(self: Self, method: str, call: Callable[[], Any], content: bytes) -> object:
        with patched_session(method, return_value=MockResponse(content=content)) as (_, close_mock, init_kwargs):
            result = await call()
            assert close_mock.await_count == 1
            assert init_kwargs[0]["timeout"].total == 10.0
        return result

    async def test_xml_mdq_get_failures(self: Self) -> None:
        await self._check_failures(
            "get", lambda: xml_mdq_get("https://rp.example.com", "http://mdq.example.com", TIMEOUT), MDQData()
        )

    async def test_xml_mdq_get_success_closes_session(self: Self) -> None:
        # unparsable xml gives empty MDQData but the session must still be closed once
        result = await self._check_success(
            "get", lambda: xml_mdq_get("https://rp.example.com", "http://mdq.example.com", TIMEOUT), b"<a"
        )
        assert result == MDQData()

    async def test_get_remote_metadata_failures(self: Self) -> None:
        await self._check_failures("get", lambda: get_remote_metadata("http://example.com/md", TIMEOUT), None)

    async def test_get_remote_metadata_success(self: Self) -> None:
        result = await self._check_success("get", lambda: get_remote_metadata("http://example.com/md", TIMEOUT), b"jws")
        assert result == "jws"

    async def test_push_interaction_finish_failures(self: Self) -> None:
        await self._check_failures(
            "post", lambda: push_interaction_finish("http://example.com/p", "h", "r", TIMEOUT), None
        )

    async def test_push_interaction_finish_success(self: Self) -> None:
        result = await self._check_success(
            "post", lambda: push_interaction_finish("http://example.com/p", "h", "r", TIMEOUT), b""
        )
        assert result is None
