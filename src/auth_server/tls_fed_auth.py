import asyncio
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp
import anyio
from aiofiles import open as async_open
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto import jwk, jws
from pydantic import BaseModel, ConfigDict, ValidationError

from auth_server.cert_utils import rfc8705_fingerprint
from auth_server.config import AuthServerConfig, TLSFEDMetadata, load_config
from auth_server.models.gnap import Key, Proof, ProofMethod
from auth_server.models.tls_fed_metadata import Entity, TLSFEDJOSEHeader
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadataModel
from auth_server.time_utils import utc_now

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# upper bound on refresh rounds a single call awaits, guards against zero length refresh delays
MAX_REFRESH_ROUNDS = 3
MIN_REFRESH_DELAY = timedelta(seconds=1)
# a previously loaded source that is no longer usable ignores refresh_at, at most one fetch per interval and source
ON_DEMAND_REFRESH_MIN_INTERVAL = timedelta(seconds=10)


class MetadataSource(BaseModel):
    issued_at: datetime
    expires_at: datetime
    issuer: str
    metadata: TLSFEDMetadataModel


class MetadataEntity(Entity):
    issuer: str
    expires_at: datetime
    model_config = ConfigDict(frozen=True)


class IssuerMetadata(BaseModel):
    issuer: str
    issued_at: datetime
    renew_at: datetime
    expires_at: datetime
    entities: Mapping[str, MetadataEntity]
    model_config = ConfigDict(frozen=True)


class Metadata(BaseModel):
    issuer_metadata: Mapping[str, IssuerMetadata]
    model_config = ConfigDict(frozen=True)


async def load_jwks(path: Path) -> jwk.JWKSet | None:
    try:
        async with await anyio.open_file(path) as f:
            jwks = jwk.JWKSet.from_json(await f.read())
        logger.info(f"jwks loaded from {path}")
        return jwks
    except OSError as e:
        logger.error(f"Could not open {path}: {e}")
    return None


async def get_remote_metadata(url: str) -> str | None:
    timeout = load_config().http_client_timeout
    # Get remote metadata jws
    logger.debug(f"Trying {url}")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout.total_seconds())) as session:
            response = await session.get(url=url)
            if response.status != 200:
                logger.error(f"{url} returned {response.status}")
                return None
            text = await response.text()
    except (aiohttp.ClientError, TimeoutError):
        logger.exception(f"Failed to get remote metadata from {url}")
        return None
    logger.debug(f"Received {text}")
    return text


async def get_local_metadata(path: Path) -> str | None:
    # Open local jws file
    try:
        async with async_open(path) as f:
            return await f.read()
    except OSError as e:
        logger.error(f"Could not open {path}: {e}")
    return None


async def load_metadata_source(
    raw_jws: str | None, jwks: jwk.JWKSet | None, source: TLSFEDMetadata
) -> MetadataSource | None:
    logger.info(f"loading metadata from source: {source}")
    if raw_jws is None:
        logger.warning("could not load metadata. missing jws")
        return None
    if jwks is None:
        logger.warning("could not load metadata. missing jwks")
        return None

    _jws = jws.JWS()

    try:
        # deserialize jws
        _jws.deserialize(raw_jws=raw_jws)
    except (jws.InvalidJWSObject, IndexError):
        logger.exception("metadata could not be deserialized")
        return None

    # load JOSE headers
    headers = list()
    logger.debug(f"jose_header: {_jws.jose_header}")
    if isinstance(_jws.jose_header, list):
        headers = list(_jws.jose_header)
    elif isinstance(_jws.jose_header, dict):
        headers.append(_jws.jose_header)

    jose_headers = []
    for item in headers:
        try:
            jose_headers.append(TLSFEDJOSEHeader.model_validate(item))
        except ValidationError:
            logger.exception("header could not be validated")
            continue

    # verify jws
    verified = False
    jose_header = None
    for header in jose_headers:
        try:
            _jws.verify(key=jwks.get_key(kid=header.kid))
            verified = True
            jose_header = header
            break
        except jws.InvalidJWSSignature:
            logger.debug("invalid JWS signature")
            continue

    if not verified:
        logger.exception("metadata could not be verified")
        return None

    # validate jws
    assert jose_header is not None  # please mypy
    logger.debug(f"payload: {_jws.payload}")
    try:
        # validate payload structure
        metadata = TLSFEDMetadataModel.model_validate_json(_jws.payload)
        # Try both header and payload until RFC9932 is in effect, payload takes precedence
        iat = metadata.iat or jose_header.iat
        exp = metadata.exp or jose_header.exp
        iss = metadata.iss or jose_header.iss
        return MetadataSource(issued_at=iat, expires_at=exp, issuer=iss, metadata=metadata)
    except ValidationError:
        logger.exception("metadata could not be validated")
        # if strict we do not try to load partial metadata
        if source.strict:
            return None

    # Try to load any entities that validates
    payload = json.loads(_jws.payload)
    # split out entities to load them one by one
    entities = payload.pop("entities")
    payload["entities"] = []  # entities can not be missing
    try:
        metadata = TLSFEDMetadataModel.model_validate(payload)
    except ValidationError:
        logger.exception("partial metadata could not be validated")
        # if there is something wrong with the base structure of the metadata, give up
        return None

    # Try both header and payload until RFC9932 is in effect, payload takes precedence
    iat = metadata.iat or jose_header.iat  # technically
    exp = metadata.exp or jose_header.exp
    iss = metadata.iss or jose_header.iss
    if not all([iat, exp, iss]):
        logger.error(f"Missing required fields: {iat=}, {exp=}, {iss=}")
        return None

    # validate entities and discard the ones failing
    for entity in entities:
        try:
            metadata.entities.append(Entity.model_validate(entity))
        except ValidationError:
            logger.exception(f"Failed to parse {entity.get('entity_id')} from {iss} metadata")
            continue
    return MetadataSource(issued_at=iat, expires_at=exp, issuer=iss, metadata=metadata)


def _build_issuer_metadata(metadata_source: MetadataSource, now: datetime, cache_ttl: timedelta) -> IssuerMetadata:
    logger.info(f"loading metadata for issuer: {metadata_source.issuer}")
    # Set renew_at to the issuer's cache_ttl if available, otherwise the configured default
    renew_at = now + cache_ttl
    if metadata_source.metadata.cache_ttl is not None:
        renew_at = now + timedelta(seconds=metadata_source.metadata.cache_ttl)
    logger.info(f"metadata from {metadata_source.issuer} should be renewed at {renew_at}")
    # Parse entities
    entities = {}
    for entity in metadata_source.metadata.entities:
        entities[str(entity.entity_id)] = MetadataEntity(
            issuer=metadata_source.issuer,
            expires_at=metadata_source.expires_at,
            **entity.model_dump(exclude_unset=True),
        )
    return IssuerMetadata(
        issuer=metadata_source.issuer,
        issued_at=metadata_source.issued_at,
        renew_at=renew_at,
        expires_at=metadata_source.expires_at,
        entities=entities,
    )


async def _load_source(source: TLSFEDMetadata, cache_ttl: timedelta) -> IssuerMetadata | None:
    raw_jws = None
    jwks = await load_jwks(source.jwks)
    # Try local source if it exists
    if source.local is not None:
        logger.info(f"loading metadata from: {source.local}")
        raw_jws = await get_local_metadata(source.local)
        logger.debug(f"{source.local} returned jws: {raw_jws}")
    # if there is no local source try remote source if it exists
    elif source.remote is not None:
        logger.info(f"loading metadata from: {source.remote}")
        raw_jws = await get_remote_metadata(str(source.remote))
        logger.debug(f"{source.remote} returned jws: {raw_jws}")
    metadata_source = await load_metadata_source(raw_jws=raw_jws, jwks=jwks, source=source)
    if metadata_source is None:
        return None
    logger.debug(f"loaded metadata source: {metadata_source}")
    issuer_metadata = _build_issuer_metadata(metadata_source, now=utc_now(), cache_ttl=cache_ttl)
    now = utc_now()
    if now > issuer_metadata.expires_at:
        logger.warning(f"metadata from {issuer_metadata.issuer} is already expired {issuer_metadata.expires_at}")
        return None
    if now < issuer_metadata.issued_at:
        # build_metadata would not serve it, so it must not replace the last good copy either
        logger.warning(
            f"metadata from {issuer_metadata.issuer} is not valid yet, issued at {issuer_metadata.issued_at}"
        )
        return None
    return issuer_metadata


@dataclass
class _SourceState:
    issuer_metadata: IssuerMetadata | None = None  # last good data
    refresh_at: datetime = datetime.min.replace(tzinfo=UTC)  # due immediately
    last_attempt_at: datetime | None = None  # start of the latest refresh attempt, success or not
    failures: int = 0
    stale_warned: bool = False  # stale-serving warning already logged this refresh cycle
    dropped_logged: bool = False  # grace-elapsed error already logged this refresh cycle


@dataclass
class _TLSFedMetadataCache:
    """
    Per source refresh state, keyed by source identity (str(remote or local)) so reordering the configured sources
    does not swap state between them. Sources with identical identity get the list index appended.

    The cache is module-global and bound to a single event loop. A config change (sources added, removed or edited)
    requires clear_tls_fed_metadata_cache(); states of sources missing from the config are also pruned on use.
    """

    states: dict[str, _SourceState] = field(default_factory=dict)
    _refresh_task: asyncio.Task[None] | None = None

    def reset(self) -> None:
        task = self._refresh_task
        self._refresh_task = None
        self.states = {}
        if task is not None and not task.done():
            try:
                task.cancel()
            except RuntimeError:
                # task belongs to a closed event loop
                pass

    @staticmethod
    def sources(config: AuthServerConfig) -> dict[str, TLSFEDMetadata]:
        result: dict[str, TLSFEDMetadata] = {}
        for i, source in enumerate(config.tls_fed_metadata):
            key = str(source.remote or source.local)
            if key in result:
                key = f"{key}#{i}"
                while key in result:
                    key = f"{key}#{i}"
            result[key] = source
        return result

    def _state(self, key: str) -> _SourceState:
        return self.states.setdefault(key, _SourceState())

    def prune(self, config: AuthServerConfig) -> None:
        keys = self.sources(config).keys()
        for key in [k for k in self.states if k not in keys]:
            del self.states[key]

    def due_sources(self, config: AuthServerConfig, now: datetime) -> list[str]:
        self.prune(config)
        due = []
        for key in self.sources(config):
            state = self._state(key)
            # a source is also due when clients are rejected for lack of data: do not wait out the backoff of an
            # earlier failure
            on_demand = (
                state.issuer_metadata is not None
                and not self.is_usable(key, now, config)
                and (state.last_attempt_at is None or now - state.last_attempt_at >= ON_DEMAND_REFRESH_MIN_INTERVAL)
            )
            if now >= state.refresh_at or on_demand:
                due.append(key)
        return due

    def is_usable(self, key: str, now: datetime, config: AuthServerConfig) -> bool:
        """Data may be used for decisions until renew_at, then only for a short grace while refreshes fail."""
        issuer_metadata = self._state(key).issuer_metadata
        if issuer_metadata is None or now > issuer_metadata.expires_at:
            return False
        if now <= issuer_metadata.renew_at:
            return True
        return now <= issuer_metadata.renew_at + config.tls_fed_metadata_stale_grace

    def build_metadata(self, config: AuthServerConfig, now: datetime) -> Metadata:
        """Only sources that are usable per is_usable and currently valid are included."""
        loaded: dict[str, IssuerMetadata] = {}
        for key in self.sources(config):
            state = self._state(key)
            issuer_metadata = state.issuer_metadata
            if issuer_metadata is None:
                continue
            if not self.is_usable(key, now, config):
                if not state.dropped_logged:
                    state.dropped_logged = True
                    if now > issuer_metadata.expires_at:
                        logger.error(
                            f"tls fed metadata source {key} ({issuer_metadata.issuer}) metadata expired at "
                            f"{issuer_metadata.expires_at}, dropping it"
                        )
                    else:
                        logger.error(
                            f"tls fed metadata source {key} ({issuer_metadata.issuer}) grace period elapsed without a "
                            f"successful refresh, dropping it (renew_at {issuer_metadata.renew_at}, "
                            f"grace ended {issuer_metadata.renew_at + config.tls_fed_metadata_stale_grace})"
                        )
                continue
            if not issuer_metadata.issued_at <= now <= issuer_metadata.expires_at:
                logger.debug(f"tls fed metadata source {key} ({issuer_metadata.issuer}) is not valid at {now}")
                continue
            if now > issuer_metadata.renew_at and not state.stale_warned:
                state.stale_warned = True
                logger.warning(
                    f"serving stale tls fed metadata for source {key} ({issuer_metadata.issuer}), renew_at "
                    f"{issuer_metadata.renew_at} passed and refresh failing, "
                    f"grace ends {issuer_metadata.renew_at + config.tls_fed_metadata_stale_grace}"
                )
            loaded[issuer_metadata.issuer] = issuer_metadata
        return Metadata(issuer_metadata=loaded)

    async def _refresh_source(self, key: str, config: AuthServerConfig) -> None:
        source = self.sources(config).get(key)
        if source is None:
            return
        state = self._state(key)
        state.last_attempt_at = utc_now()
        try:
            result = await _load_source(source, cache_ttl=config.tls_fed_metadata_cache_ttl)
        except Exception:
            logger.exception(f"unexpected error loading tls fed metadata source {key}")
            result = None
        now = utc_now()
        if result is not None:
            state.issuer_metadata = result
            state.refresh_at = min(result.renew_at, result.expires_at)
            state.failures = 0
            state.stale_warned = False
            state.dropped_logged = False
            return
        # never back off longer than the stale grace, or a recovered remote stays rejected after the source is dropped
        # the floor keeps the delay positive whatever the config says (config.model_construct skips validation)
        delay = max(
            MIN_REFRESH_DELAY,
            min(
                config.tls_fed_metadata_retry_interval * 2 ** min(state.failures, 16),
                config.tls_fed_metadata_cache_ttl,
                config.tls_fed_metadata_stale_grace,
            ),
        )
        state.refresh_at = now + delay
        state.failures += 1
        logger.warning(
            f"failed to refresh tls fed metadata source {key}, keeping last good data, retrying at {state.refresh_at}"
        )

    async def _refresh(self, keys: list[str], config: AuthServerConfig) -> None:
        try:
            await asyncio.gather(*[self._refresh_source(k, config) for k in keys])
        except Exception:
            logger.exception("tls fed metadata refresh failed")

    def ensure_task(self, keys: list[str], config: AuthServerConfig) -> asyncio.Task[None]:
        task = self._refresh_task
        if task is not None:
            try:
                usable = (
                    not task.done()
                    and task.get_loop() is asyncio.get_running_loop()
                    and not task.get_loop().is_closed()
                )
            except RuntimeError:
                usable = False
            if usable:
                return task
        task = asyncio.create_task(self._refresh(keys, config))
        self._refresh_task = task
        return task


_cache = _TLSFedMetadataCache()


def clear_tls_fed_metadata_cache() -> None:
    _cache.reset()


def _schedule_refresh(config: AuthServerConfig, now: datetime) -> asyncio.Task[None] | None:
    """
    Start (or join) the shared refresh task for due sources without waiting for it. Returns the task only when a due
    source has never loaded (cold start) and callers may want to wait for it, everything else refreshes in the
    background and is served or dropped according to is_usable.
    """
    due = _cache.due_sources(config, now)
    if not due:
        return None
    task = _cache.ensure_task(due, config)
    if all(_cache._state(k).issuer_metadata is not None for k in due):
        return None
    return task


async def _wait_for_refresh(task: asyncio.Task[None], config: AuthServerConfig) -> bool:
    """Wait for a cold start refresh, bounded by http_client_timeout. Returns False when waiting should stop."""
    # asyncio.wait neither cancels the shared task on timeout or caller cancellation, nor raises when the task itself
    # was cancelled (clear_tls_fed_metadata_cache): it just reports it as done. Cancelling this request still raises
    # CancelledError here, which is deliberately not caught.
    done, _ = await asyncio.wait({task}, timeout=config.http_client_timeout.total_seconds())
    if not done:
        logger.warning("timed out waiting for initial tls fed metadata load")
        return False
    if task.cancelled():
        # the refresh task was cancelled by clear_tls_fed_metadata_cache, serve what the cache holds now
        return False
    task.exception()  # mark as retrieved, _refresh logs its own failures
    return True


async def get_tls_fed_metadata() -> Metadata:
    config = load_config()
    for _ in range(MAX_REFRESH_ROUNDS):
        task = _schedule_refresh(config, utc_now())
        if task is None or not await _wait_for_refresh(task, config):
            break
    return _cache.build_metadata(config, utc_now())


def _find_entity(metadata: Metadata, entity_id: str, now: datetime) -> MetadataEntity | None:
    for issuer, issuer_metadata in metadata.issuer_metadata.items():
        # Check if metadata is valid
        # not before issued_at
        if now < issuer_metadata.issued_at:
            logger.error(f"Metadata for issuer {issuer} is not valid yet (issued at {issuer_metadata.issued_at})")
            continue
        # not after expires_at
        if now > issuer_metadata.expires_at:
            logger.error(f"Metadata for issuer {issuer} has expired {issuer_metadata.expires_at}")
            continue

        # Get entity from metadata
        entity = issuer_metadata.entities.get(entity_id)
        if not entity:
            logger.info(f"{entity_id} not found in {issuer} metadata")
            continue

        return entity

    return None


async def get_entity(entity_id: str) -> MetadataEntity | None:
    config = load_config()
    now = utc_now()
    pending = _schedule_refresh(config, now)
    # look in what is servable right now first, a cold source must not delay clients found in a usable one
    entity = _find_entity(_cache.build_metadata(config, now), entity_id, now)
    if entity is not None or pending is None:
        return entity
    # cache miss with a cold source loading, wait for it (bounded) and look again
    metadata = await get_tls_fed_metadata()
    return _find_entity(metadata, entity_id, utc_now())


async def entity_to_keys(entity: MetadataEntity | None) -> list[Key]:
    keys: list[Key] = []
    if entity is None:
        return keys

    certs = [
        load_pem_x509_certificate(item.x509certificate.encode())
        for item in entity.issuers
        if item.x509certificate is not None
    ]
    for cert in certs:
        _fingerprint = rfc8705_fingerprint(cert)
        logger.info(f"Found cert in metadata, S256: {_fingerprint}")
        keys.append(
            Key(
                proof=Proof(method=ProofMethod.MTLS),
                cert_S256=_fingerprint,
            )
        )
    return keys
