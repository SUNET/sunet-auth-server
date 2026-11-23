import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Self
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk
from pydantic import ValidationError

from auth_server import tls_fed_auth
from auth_server.config import AuthServerConfig, TLSFEDMetadata
from auth_server.models.jose import SupportedAlgorithms
from auth_server.tests.utils import create_cert, create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import _cache, clear_tls_fed_metadata_cache, get_entity

__author__ = "lundberg"

RETRY = timedelta(minutes=1)
GRACE = timedelta(minutes=5)
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
        # still served after failed refresh, within renew_at + grace
        self.now += GRACE - timedelta(seconds=10)
        assert await get_entity(self.entity_id) is not None

    async def test_stale_data_dropped_after_grace(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), None, None, None]
        assert await get_entity(self.entity_id) is not None
        renew_at = self.t0 + timedelta(seconds=60)
        self.now = renew_at + GRACE + timedelta(seconds=1)
        # fail closed: refresh fails, data older than renew_at + grace must not be served
        assert await get_entity(self.entity_id) is None
        assert await get_entity(self.entity_id) is None

    async def test_entity_served_again_after_recovery(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), None, self.make_jws(cache_ttl=60)]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=60) + GRACE + timedelta(seconds=1)
        assert await self.refresh_round() is None  # background refresh fails
        # backoff elapses, fetch succeeds
        self.now += RETRY * 2 + timedelta(seconds=1)
        assert await self.refresh_round() is None  # refresh runs in the background
        assert await get_entity(self.entity_id) is not None

    async def test_revoked_entity_rejected_after_refresh(self: Self) -> None:
        self.mock_remote.side_effect = [
            self.make_jws(cache_ttl=60),
            self.make_jws(cache_ttl=60, entity_id="https://other.example.com"),
        ]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=61)
        # stale copy still contains entity and may be served while refresh runs in the background
        task = None
        await get_entity(self.entity_id)
        task = _cache._refresh_task
        assert task is not None
        await task
        assert await get_entity(self.entity_id) is None
        assert await get_entity("https://other.example.com") is not None

    async def test_stale_warning_once_per_cycle(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), None, None, None]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=61)
        with self.assertLogs("auth_server.tls_fed_auth", level="WARNING") as cm:
            for _ in range(5):
                assert await get_entity(self.entity_id) is not None
        stale = [r for r in cm.records if "serving stale" in r.getMessage()]
        assert len(stale) == 1
        assert "renew_at" in stale[0].getMessage()
        # drop error logged once as well
        task = _cache._refresh_task
        assert task is not None
        await task
        self.now = self.t0 + timedelta(seconds=60) + GRACE + timedelta(seconds=1)
        with self.assertLogs("auth_server.tls_fed_auth", level="ERROR") as cm:
            for _ in range(3):
                assert await get_entity(self.entity_id) is None
        dropped = [r for r in cm.records if "dropping it" in r.getMessage()]
        assert len(dropped) == 1

    async def test_is_usable_boundaries(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60)]
        await get_entity(self.entity_id)
        config = tls_fed_auth.load_config()
        renew_at = self.t0 + timedelta(seconds=60)
        eps = timedelta(microseconds=1)
        assert _cache.is_usable(0, renew_at, config)
        assert _cache.is_usable(0, renew_at + eps, config)
        assert _cache.is_usable(0, renew_at + GRACE, config)
        assert not _cache.is_usable(0, renew_at + GRACE + eps, config)
        assert not _cache.is_usable(5, renew_at, config)

    async def test_is_usable_expires_before_grace_end(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60, expires=timedelta(seconds=90))]
        await get_entity(self.entity_id)
        config = tls_fed_auth.load_config()
        expires_at = _cache.states[0].issuer_metadata.expires_at  # type: ignore[union-attr]
        eps = timedelta(microseconds=1)
        assert expires_at < self.t0 + timedelta(seconds=60) + GRACE
        assert _cache.is_usable(0, expires_at, config)
        assert not _cache.is_usable(0, expires_at + eps, config)

    async def test_expiry_forces_reload(self: Self) -> None:
        later = self.t0 + timedelta(minutes=10, seconds=30)
        self.mock_remote.side_effect = [
            self.make_jws(expires=timedelta(minutes=10)),
            self.make_jws(issue_time=later, entity_id="https://other.example.com"),
        ]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(minutes=11)
        # old data expired, dropped at once while the refresh runs in the background
        assert await get_entity(self.entity_id) is None
        task = _cache._refresh_task
        assert task is not None
        await task
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

    async def refresh_round(self: Self, entity_id: str | None = None) -> object:
        result = await get_entity(entity_id or self.entity_id)
        task = _cache._refresh_task
        if task is not None:
            await task
        return result

    async def test_backoff_capped_by_grace(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60)] + [None] * 8 + [self.make_jws(cache_ttl=60)]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=60) + GRACE + timedelta(seconds=1)
        for _ in range(8):
            assert await self.refresh_round() is None
            assert _cache.states[0].refresh_at - self.now <= GRACE
            self.now += GRACE + timedelta(seconds=1)
        assert _cache.states[0].failures == 8
        # remote recovers, entity served within one grace
        assert await self.refresh_round() is None
        assert _cache.states[0].failures == 0
        assert await get_entity(self.entity_id) is not None

    async def test_zero_delay_terminates(self: Self) -> None:
        config = AuthServerConfig.model_construct(
            auth_token_issuer="https://auth.example.com",
            tls_fed_metadata=[TLSFEDMetadata(remote=URL_A, jwks=self.datadir / "tls_fed_jwks.json")],
            tls_fed_metadata_retry_interval=timedelta(0),
            tls_fed_metadata_cache_ttl=timedelta(0),
            tls_fed_metadata_stale_grace=timedelta(0),
            http_client_timeout=timedelta(seconds=10),
        )
        patch("auth_server.tls_fed_auth.load_config", return_value=config).start()
        self.mock_remote.return_value = None
        assert await asyncio.wait_for(get_entity(self.entity_id), timeout=5) is None
        # the delay floor makes the source not due again at the same instant: one fetch, not a spin
        assert self.mock_remote.await_count == 1
        assert await asyncio.wait_for(get_entity(self.entity_id), timeout=5) is None
        assert self.mock_remote.await_count == 1

    async def test_hanging_refresh_after_grace_does_not_block(self: Self) -> None:
        event = asyncio.Event()
        jws_new = self.make_jws(cache_ttl=60)

        async def hang(*args: object, **kwargs: object) -> str:
            await event.wait()
            return jws_new

        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), hang]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=60) + GRACE + timedelta(seconds=1)
        self.mock_remote.side_effect = hang
        assert await asyncio.wait_for(get_entity(self.entity_id), timeout=1) is None
        task = _cache._refresh_task
        assert task is not None
        assert not task.done()
        event.set()
        await task
        assert await get_entity(self.entity_id) is not None

    async def test_drop_log_messages_distinct(self: Self) -> None:
        self.mock_remote.side_effect = [self.make_jws(cache_ttl=60), None]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(seconds=60) + GRACE + timedelta(seconds=1)
        with self.assertLogs("auth_server.tls_fed_auth", level="ERROR") as cm:
            for _ in range(2):
                assert await self.refresh_round() is None
        msgs = [r.getMessage() for r in cm.records if "dropping it" in r.getMessage()]
        assert len(msgs) == 1
        assert "grace period elapsed" in msgs[0]

        clear_tls_fed_metadata_cache()
        self.mock_remote.side_effect = [self.make_jws(expires=timedelta(minutes=10)), None]
        assert await get_entity(self.entity_id) is not None
        self.now = self.t0 + timedelta(minutes=11)
        with self.assertLogs("auth_server.tls_fed_auth", level="ERROR") as cm:
            for _ in range(2):
                assert await self.refresh_round() is None
        msgs = [r.getMessage() for r in cm.records if "dropping it" in r.getMessage()]
        assert len(msgs) == 1
        assert "metadata expired" in msgs[0]

    def test_config_grace_must_cover_retry_interval(self: Self) -> None:
        kwargs: dict[str, Any] = {"auth_token_issuer": "https://auth.example.com"}
        with self.assertRaises(ValidationError) as cm:
            AuthServerConfig(
                tls_fed_metadata_retry_interval=timedelta(minutes=2),
                tls_fed_metadata_stale_grace=timedelta(minutes=1),
                **kwargs,
            )
        assert "tls_fed_metadata_stale_grace" in str(cm.exception)
        AuthServerConfig(
            tls_fed_metadata_retry_interval=timedelta(minutes=1),
            tls_fed_metadata_stale_grace=timedelta(minutes=1),
            **kwargs,
        )

    def test_config_rejects_non_positive_durations(self: Self) -> None:
        for name in ("tls_fed_metadata_retry_interval", "tls_fed_metadata_cache_ttl", "http_client_timeout"):
            for value in (timedelta(0), timedelta(seconds=-1)):
                with self.assertRaises(ValidationError):
                    AuthServerConfig(auth_token_issuer="https://auth.example.com", **{name: value})  # type: ignore[arg-type]
