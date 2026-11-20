import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Self
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk

from auth_server.config import AuthServerConfig, TLSFEDMetadata
from auth_server.models.jose import SupportedAlgorithms
from auth_server.tests.utils import create_cert, create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import _cache, clear_tls_fed_metadata_cache, get_entity

__author__ = "lundberg"

RETRY = timedelta(minutes=1)
URL_A = "https://a.example.com/metadata.jws"
URL_B = "https://b.example.com/metadata.jws"


class TestTLSFedMetadataCache(IsolatedAsyncioTestCase):
    def setUp(self: Self) -> None:
        clear_tls_fed_metadata_cache()
        self.datadir = Path(__file__).with_name("data")
        with open(self.datadir / "tls_fed_jwks.json") as f:
            self.jwks = jwk.JWKSet()
            self.jwks.import_keyset(f.read())
        _, cert = create_cert(common_name="client.example.com")
        self.cert_str = cert.public_bytes(Encoding.PEM).decode()
        self.t0 = utc_now() + timedelta(seconds=1)
        self.now = self.t0
        self.entity_id = "https://client.example.com"

        self.patches = [
            patch("auth_server.tls_fed_auth.utc_now", side_effect=lambda: self.now),
        ]
        for p in self.patches:
            p.start()
        self.mock_remote = patch("auth_server.tls_fed_auth.get_remote_metadata", new_callable=AsyncMock).start()
        self.set_config([URL_A])

    def tearDown(self: Self) -> None:
        patch.stopall()
        clear_tls_fed_metadata_cache()

    def set_config(self: Self, urls: list[str]) -> None:
        config = AuthServerConfig(
            auth_token_issuer="https://auth.example.com",
            tls_fed_metadata=[TLSFEDMetadata(remote=url, jwks=self.datadir / "tls_fed_jwks.json") for url in urls],
            tls_fed_metadata_retry_interval=RETRY,
        )
        patch("auth_server.tls_fed_auth.load_config", return_value=config).start()

    def make_jws(
        self: Self,
        issue_time: datetime | None = None,
        expires: timedelta = timedelta(days=14),
        cache_ttl: int = 3600,
        entity_id: str | None = None,
        issuer: str = "metadata.example.com",
    ) -> str:
        issue_time = issue_time or self.t0
        metadata = create_tls_fed_metadata(
            entity_id=entity_id or self.entity_id,
            client_certs=[self.cert_str],
            issuer=issuer,
            expires=expires,
            cache_ttl=cache_ttl,
            issue_time=issue_time,
        )
        return tls_fed_metadata_to_jws(
            metadata,
            key=self.jwks.get_key("metadata_signing_key_id"),
            issuer=issuer,
            expires=expires,
            alg=SupportedAlgorithms.ES256,
            issue_time=issue_time,
        ).decode()

    async def test_failure_not_cached_forever(self: Self) -> None:
        self.mock_remote.side_effect = [None, self.make_jws()]
        assert await get_entity(self.entity_id) is None
        self.now += RETRY + timedelta(seconds=1)
        entity = await get_entity(self.entity_id)
        assert entity is not None
        assert self.mock_remote.await_count == 2

    async def test_failure_within_retry_window_no_refetch(self: Self) -> None:
        self.mock_remote.side_effect = [None, self.make_jws()]
        assert await get_entity(self.entity_id) is None
        self.now += RETRY / 2
        assert await get_entity(self.entity_id) is None
        assert self.mock_remote.await_count == 1

    async def test_last_good_data_served(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), None]
        assert await get_entity(self.entity_id) is not None
        self.now += timedelta(seconds=61)
        assert await get_entity(self.entity_id) is not None
        task = _cache._refresh_task
        assert task is not None
        await task
        assert _cache.states[0].failures == 1
        assert self.mock_remote.await_count == 2
        # still served after failed refresh
        assert await get_entity(self.entity_id) is not None

    async def test_expiry_forces_reload(self: Self) -> None:
        later = self.t0 + timedelta(minutes=10, seconds=30)
        self.mock_remote.side_effect = [
            self.make_jws(expires=timedelta(minutes=10)),
            self.make_jws(issue_time=later, entity_id="https://other.example.com"),
        ]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(minutes=11)
        # old data expired, must wait for fresh data
        assert await get_entity("https://other.example.com") is not None
        assert await get_entity(self.entity_id) is None
        assert self.mock_remote.await_count == 2

    async def test_expired_data_and_failed_refresh(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(expires=timedelta(minutes=10)), None]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(minutes=11)
        assert await get_entity(self.entity_id) is None

    async def test_no_thundering_herd(self: Self) -> None:
        event = asyncio.Event()
        jws = self.make_jws()

        async def fetch(*args: object, **kwargs: object) -> str:
            await event.wait()
            return jws

        self.mock_remote.side_effect = fetch
        calls = asyncio.gather(*[get_entity(self.entity_id) for _ in range(10)])
        for _ in range(5):
            await asyncio.sleep(0)
        event.set()
        results = await calls
        assert all(r is not None for r in results)
        assert self.mock_remote.await_count == 1

    async def test_one_source_fails(self: Self) -> None:
        self.set_config([URL_A, URL_B])
        jws_b = self.make_jws(entity_id="https://b-client.example.com", issuer="b.example.com")

        async def fetch(url: str, **kwargs: object) -> str | None:
            return jws_b if url == URL_B else None

        self.mock_remote.side_effect = fetch
        assert await get_entity("https://b-client.example.com") is not None
        assert await get_entity(self.entity_id) is None
        assert _cache.states[0].failures == 1
        assert _cache.states[1].failures == 0
