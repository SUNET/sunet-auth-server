from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Coroutine, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from logging import getLogger
from typing import Any, Self

from pygamlastan import metadata as pg_metadata
from pygamlastan.compat.saml2.config import SPConfig
from pygamlastan.compat.saml2.mdstore import MetaDataMDX, MetadataStore
from pygamlastan.compat.saml2.s_utils import UnknownSystemEntity
from pygamlastan.crypto import SamlVerifier

from auth_server.mdq import fetch_mdq_xml
from auth_server.time_utils import utc_now

__author__ = "lundberg"

logger = getLogger(__name__)

# How long a looked up entity is trusted before it is fetched again (never longer than its validUntil)
MDQ_CACHE_TTL_SECONDS = 3600.0
# How long a failed lookup is remembered, so that a bad entity id does not turn into a request flood
MDQ_NEGATIVE_CACHE_TTL_SECONDS = 60.0
# Upper bound on the number of entities (and failed lookups) kept per source, the keys come from request input
MDQ_CACHE_MAX_ENTRIES = 1024
# How long past its refresh time a good copy may still be used when refreshing it fails (about one extra refresh
# ttl). The copy is never used past its validUntil either, which every MDQ document must carry.
MDQ_MAX_STALE_SECONDS = 3600.0
# Earliest retry of a local/remote metadata source refresh that failed (or found nothing newer)
METADATA_REFRESH_RETRY_SECONDS = 60.0


@dataclass
class _CacheEntry:
    entity: pg_metadata.EntityDescriptor | None  # None for a failed lookup
    refresh_at: float  # monotonic time, look up again after this
    drop_at: float  # monotonic time, do not use (or keep) the entity after this


def run_coroutine_sync[T](coro: Coroutine[Any, Any, T]) -> T:
    """
    Run a coroutine from synchronous code that is not running inside an event loop (scripts, tests).

    The pygamlastan compat layer is synchronous but the MDQ fetch code is async. Inside a running event loop this
    must never be used, it would block the loop on network I/O. The async code paths prefetch the entity with
    MDQMetadataSource.prefetch() before calling into the synchronous SAML client instead.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    coro.close()
    raise RuntimeError("run_coroutine_sync can not be used from a running event loop")


def _loop_is_running() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


class MDQMetadataSource(MetaDataMDX):
    """
    On-demand metadata source backed by an MDQ server, for the pygamlastan compat metadata store.

    Fetching is done with the same code as the MDQFlow (auth_server.mdq.fetch_mdq_xml). The url is the base url of the
    MDQ service as in the pysaml2 `mdq` metadata setting, the entities are fetched from <url>/entities/{sha1}<hash>.
    If a cert is configured the metadata must carry a valid signature, from that cert, over the document root.
    """

    def __init__(
        self: Self,
        url: str,
        cert: str | None = None,
        ttl: float = MDQ_CACHE_TTL_SECONDS,
        negative_ttl: float = MDQ_NEGATIVE_CACHE_TTL_SECONDS,
        max_entries: int = MDQ_CACHE_MAX_ENTRIES,
        max_stale: float = MDQ_MAX_STALE_SECONDS,
    ) -> None:
        self.url = url.rstrip("/")
        self.cert = cert
        if cert is None:
            logger.warning(
                f"MDQ source {self.url} has no cert: its metadata is trusted on the HTTPS connection only, "
                "not on a federation signature. Configure a cert pinning the federation signing key."
            )
        # Read and parse the cert once, a broken cert must stop the config load and not fail every lookup
        self._verifier = self._load_verifier(cert) if cert is not None else None
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.max_entries = max_entries
        self.max_stale = max_stale
        # entity id -> entry, oldest insert first. The keys come from request input so the size is bounded.
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        # entity id -> the fetch in flight, so concurrent prefetches of one entity share a single request
        self._inflight: dict[str, asyncio.Task[pg_metadata.EntityDescriptor | None]] = {}

    @staticmethod
    def _load_verifier(cert: str) -> SamlVerifier:
        try:
            with open(cert, "rb") as f:
                return SamlVerifier.from_cert(f.read())
        except Exception as e:
            raise RuntimeError(f"MDQ metadata signing cert {cert} could not be loaded: {e}") from e

    @property
    def mdq_url(self: Self) -> str:
        return f"{self.url}/entities"

    def _cached(self: Self, entity_id: str) -> tuple[bool, pg_metadata.EntityDescriptor | None]:
        hit = self._cache.get(entity_id)
        if hit is not None and hit.refresh_at > time.monotonic():
            return True, hit.entity
        return False, None

    def _store(self: Self, entity_id: str, entry: _CacheEntry) -> None:
        """Insert in the cache, dropping expired entries first and then the oldest ones if it is full."""
        now = time.monotonic()
        for key in [key for key, old in self._cache.items() if old.drop_at <= now]:
            del self._cache[key]
        self._cache.pop(entity_id, None)
        self._cache[entity_id] = entry
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    async def prefetch(self: Self, entity_id: str) -> pg_metadata.EntityDescriptor | None:
        """
        Look up an entity, from the cache if possible, otherwise from the MDQ server.

        A failed refresh never replaces a previous good copy, that is kept (and retried after the negative ttl) until
        it is no longer valid. Only when there is no good copy is the failure remembered as a negative entry.
        """
        found, entity = self._cached(entity_id)
        if found:
            return entity
        task = self._inflight.get(entity_id)
        if task is None or task.get_loop() is not asyncio.get_running_loop():
            task = asyncio.ensure_future(self._fetch(entity_id))
            self._inflight[entity_id] = task
        # shield: a cancelled caller must not cancel the fetch the other callers wait for
        return await asyncio.shield(task)

    async def _fetch(self: Self, entity_id: str) -> pg_metadata.EntityDescriptor | None:
        try:
            now = time.monotonic()
            previous = self._cache.get(entity_id)
            xml = await fetch_mdq_xml(entity_id=entity_id, mdq_url=self.mdq_url)
            parsed = self._parse(entity_id, xml) if xml is not None else None
            if parsed is not None:
                entity, ttl, max_age = parsed
                self._store(entity_id, _CacheEntry(entity, now + ttl, now + max_age))
                return entity
            if previous is not None and previous.entity is not None and previous.drop_at > now:
                logger.warning(f"MDQ refresh of {entity_id} failed, keeping the last good metadata")
                self._store(entity_id, _CacheEntry(previous.entity, now + self.negative_ttl, previous.drop_at))
                return previous.entity
            self._store(entity_id, _CacheEntry(None, now + self.negative_ttl, now + self.negative_ttl))
            return None
        finally:
            self._inflight.pop(entity_id, None)

    def _parse(self: Self, entity_id: str, xml: str) -> tuple[pg_metadata.EntityDescriptor, float, float] | None:
        """
        Returns the entity, seconds until it should be refreshed and seconds until it must not be used any more.

        A document without a (finite) validUntil is refused, like the library does for `remote` metadata, so a
        signing cert of an IdP can not stay in use because nobody ever declared when the metadata stops being valid.
        The entity is usable after its refresh time for at most max_stale seconds and never past its validUntil.
        """
        try:
            document = pg_metadata.parse_document(xml)
            item = next((i for i in document.entities if i.entity.entity_id == entity_id), None)
            if item is None:
                logger.error(f"MDQ response did not contain {entity_id}")
                return None
            pg_metadata.validate_entity(item.entity)
            expiry = item.effective_valid_until
            if expiry is None:
                logger.error(f"MDQ metadata for {entity_id} has no validUntil, refusing it")
                return None
            remaining = (expiry - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                logger.error(f"MDQ metadata for {entity_id} has expired")
                return None
            ttl = min(self.ttl, remaining)
            max_age = min(remaining, ttl + self.max_stale)
            if self.cert is not None and not self._signed_by_cert(xml, document):
                logger.error(f"MDQ metadata for {entity_id} has no valid signature covering the document root")
                return None
        except Exception as e:
            logger.error(f"MDQ metadata for {entity_id} could not be used: {e!r}")
            return None
        return item.entity, ttl, max_age

    def _signed_by_cert(self: Self, xml: str, document: pg_metadata.MetadataDocument) -> bool:
        """
        True if a valid signature from the configured cert covers the document root.

        A signature covers the root if it references the root by its ID, or if it references the whole document
        (URI=""), which is the root element by definition. The latter is the only way to sign a root without an ID
        attribute. Anything else (a signature over some other element, as in an XMLDSig wrapping attack where an
        unsigned entity is placed next to a signed one) is refused.
        """
        assert self._verifier is not None  # please mypy
        accepted = {""}
        if document.root_id:
            accepted.add(document.root_id)
        return any(
            result.is_valid() and not accepted.isdisjoint(result.signed_reference_ids())
            for result in self._verifier.verify_all_enveloped(xml)
        )

    def __getitem__(self: Self, entity_id: str) -> pg_metadata.EntityDescriptor:
        found, entity = self._cached(entity_id)
        if not found:
            if _loop_is_running():
                # never block the event loop on network I/O, fail closed. The async code paths must prefetch.
                logger.error(f"MDQ lookup of {entity_id} not prefetched, refusing to fetch inside the event loop")
                raise KeyError(entity_id)
            logger.warning(f"MDQ lookup of {entity_id} not prefetched, fetching synchronously")
            entity = run_coroutine_sync(self.prefetch(entity_id))
        if entity is None:
            raise KeyError(entity_id)
        return entity


# (entities, effective validUntil per entity id, None for no deadline) of a freshly loaded local/remote source
LoadedSource = tuple[list[pg_metadata.EntityDescriptor], dict[str, datetime | None]]

_refresh_executor: ThreadPoolExecutor | None = None
_refresh_executor_lock = threading.Lock()


def _get_refresh_executor() -> ThreadPoolExecutor:
    """
    Dedicated single thread for the (blocking, urllib based) reload of local/remote metadata sources.

    The compat loader is sync only. It is not run on the default executor, which also serves getaddrinfo for aiohttp
    (a slow metadata server must not stall the MDQ and TLS federation lookups). One thread is enough, a refresh is
    rare and one source is reloaded at a time.
    """
    global _refresh_executor  # noqa: PLW0603
    with _refresh_executor_lock:
        if _refresh_executor is None:
            _refresh_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="saml-metadata-refresh")
        return _refresh_executor


@dataclass
class _Source:
    key: str  # file path or url
    entity_ids: set[str]
    loader: Callable[[], LoadedSource] | None  # sync, blocking, run in the refresh executor
    refresh_at: datetime | None  # reload after this, None when the source has no deadline (nothing to refresh before)
    task: asyncio.Future[bool] | None = field(default=None, repr=False)


class LazySPConfig(SPConfig):
    """
    SPConfig that does not guess the only IdP from metadata when entities can also come from an MDQ server.

    It also records the effective validUntil (inherited from enclosing EntitiesDescriptors) of every entity of a
    local/remote source, which the compat loader checks at load time but then throws away.
    """

    def __init__(self: Self) -> None:
        super().__init__()
        self.source_deadlines: dict[str, dict[str, datetime | None]] = {}
        self._document_deadlines: dict[str, datetime | None] = {}

    def _validate_metadata_document(self: Self, document: pg_metadata.MetadataDocument, **kwargs: Any) -> None:
        super()._validate_metadata_document(document, **kwargs)
        self._document_deadlines = {item.entity.entity_id: item.effective_valid_until for item in document.entities}

    def _load_metadata_file(self: Self, path: str) -> None:
        self._document_deadlines = {}
        super()._load_metadata_file(path)
        self.source_deadlines[path] = self._document_deadlines

    def _load_remote_metadata(self: Self, source: Any) -> None:  # noqa: ANN401
        self._document_deadlines = {}
        super()._load_remote_metadata(source)
        self.source_deadlines[str(source["url"])] = self._document_deadlines

    def only_idp(self: Self) -> str | None:
        if not self.idp and isinstance(self.metadata, LazyMetadataStore) and self.metadata.mdq_sources:
            # the MDQ entities can not be enumerated, so "the only IdP in the metadata" is not knowable
            return None
        return super().only_idp()


def reload_metadata_source(kind: str, key: str, settings: Any) -> LoadedSource:  # noqa: ANN401
    """
    Load a local file or remote source again with the compat loader (same https, size, signature and expiry checks as
    at configuration load) into a throwaway config. Blocking, never call it on the event loop.
    """
    conf = LazySPConfig()
    conf.metadata = MetadataStore()
    if kind == "local":
        conf._load_metadata_file(key)
    else:
        conf._load_remote_metadata(settings)
    return list(conf.metadata.values()), conf.source_deadlines[key]


class LazyMetadataStore(MetadataStore):
    """
    MetadataStore that resolves entities it does not know from its on-demand (MDQ) sources.

    The compat MetadataStore only knows entities from local and remote documents. All lookups (`[]`, `get()` and `in`)
    that miss are retried against the MDQMetadataSource sources. MDQ entities are not stored in the store itself, the
    source owns their lifetime (ttl, validUntil).

    Expiry: the compat store checks validUntil only when the config is loaded, but this store lives as long as the
    process. Every local/remote entity keeps its effective deadline and is dropped, fail closed (KeyError, error
    log naming the entity), as soon as a lookup finds it past that deadline. Lookups never do I/O. Sources are
    reloaded from async code (refresh_sources) once half way to their earliest deadline, a failed reload keeps the
    last good copy only until its own deadline.
    """

    def __init__(self: Self) -> None:
        self._lock = threading.RLock()
        self._data: dict[str, pg_metadata.EntityDescriptor] = {}
        self._deadlines: dict[str, datetime | None] = {}
        self._expired: set[str] = set()
        self._earliest: datetime | None = None  # earliest deadline of a live entity
        self._sources: dict[str, _Source] = {}
        super().__init__()

    @property
    def _entities(self: Self) -> dict[str, pg_metadata.EntityDescriptor]:
        """The live entities, every access of the compat base class drops the expired ones first"""
        self._purge()
        return self._data

    @_entities.setter
    def _entities(self: Self, value: dict[str, pg_metadata.EntityDescriptor]) -> None:
        self._data = value

    def _purge(self: Self) -> None:
        earliest = self._earliest
        if earliest is None or utc_now() < earliest:
            return
        with self._lock:
            now = utc_now()
            for entity_id, deadline in self._deadlines.items():
                if deadline is not None and deadline <= now and entity_id in self._data:
                    del self._data[entity_id]
                    self._expired.add(entity_id)
                    logger.error(f"SAML metadata for {entity_id} expired at {deadline.isoformat()}, refusing it")
            self._update_earliest()

    def _update_earliest(self: Self) -> None:
        deadlines = [d for e, d in self._deadlines.items() if d is not None and e in self._data]
        self._earliest = min(deadlines, default=None)

    @staticmethod
    def _refresh_point(deadlines: dict[str, datetime | None], now: datetime) -> datetime | None:
        known = [d for d in deadlines.values() if d is not None]
        if not known:
            return None
        remaining = max(min(known) - now, timedelta(0))
        return now + max(timedelta(seconds=METADATA_REFRESH_RETRY_SECONDS), remaining / 2)

    def add_source(
        self: Self,
        source: str,
        entities: list[pg_metadata.EntityDescriptor],
        deadlines: dict[str, datetime | None] | None = None,
        loader: Callable[[], LoadedSource] | None = None,
    ) -> None:
        """
        Register a local/remote source, with the effective validUntil per entity id and (optionally) the sync
        callable that reloads the source, see refresh_sources().
        """
        with self._lock:
            super().add_source(source, entities)
            deadlines = deadlines or {}
            ids = {e.entity_id for e in entities}
            for entity_id in ids:
                self._deadlines[entity_id] = deadlines.get(entity_id)
            self._update_earliest()
            self._sources[source] = _Source(
                key=source,
                entity_ids=ids,
                loader=loader,
                refresh_at=self._refresh_point({i: self._deadlines[i] for i in ids}, utc_now()) if loader else None,
            )
        self._purge()  # an entity that is already expired is not served

    def _swap_source(
        self: Self, key: str, entities: list[pg_metadata.EntityDescriptor], deadlines: dict[str, datetime | None]
    ) -> None:
        """Replace everything a source served with a fresh load, in one step"""
        fresh = MetadataStore()
        fresh.add_source(key, entities)  # checks for duplicate ids inside the source
        ids = set(fresh)
        with self._lock:
            source = self._sources[key]
            others = set(self._deadlines) - source.entity_ids
            if ids & others:
                raise ValueError(f"reloaded source {key} has entity ids that another source serves")
            for entity_id in source.entity_ids:
                self._data.pop(entity_id, None)
                self._deadlines.pop(entity_id, None)
                self._expired.discard(entity_id)
            self.metadata[key] = fresh.metadata[key]
            self._data.update({entity_id: fresh[entity_id] for entity_id in ids})
            for entity_id in ids:
                self._deadlines[entity_id] = deadlines.get(entity_id)
            source.entity_ids = ids
            source.refresh_at = self._refresh_point({i: self._deadlines[i] for i in ids}, utc_now())
            self._update_earliest()
        self._purge()

    async def _refresh_source(self: Self, key: str) -> bool:
        source = self._sources[key]
        assert source.loader is not None  # please mypy
        try:
            entities, deadlines = await asyncio.get_running_loop().run_in_executor(
                _get_refresh_executor(), source.loader
            )
            self._swap_source(key, entities, deadlines)
        except Exception as e:
            with self._lock:
                source.refresh_at = utc_now() + timedelta(seconds=METADATA_REFRESH_RETRY_SECONDS)
            logger.error(f"SAML metadata refresh of {key} failed, keeping the last good copy until it expires: {e!r}")
            return False
        logger.info(f"SAML metadata source {key} refreshed")
        return True

    async def refresh_sources(self: Self) -> None:
        """
        Reload every local/remote source that is past its refresh point (half way to its earliest validUntil).

        Never blocks the event loop, the (sync) load runs in a dedicated one thread executor. Concurrent calls share
        one reload per source. A source with entities that are already expired is awaited, so that the request that
        found it can be served from the new copy. Otherwise the reload runs in the background and the last good copy
        keeps being served until its own deadline. Lookups never refresh, call this before them.
        """
        self._purge()
        now = utc_now()
        loop = asyncio.get_running_loop()
        waiting: list[asyncio.Future[bool]] = []
        for key, source in list(self._sources.items()):
            if source.loader is None or source.refresh_at is None or now < source.refresh_at:
                continue
            task = source.task
            if task is None or task.done() or task.get_loop() is not loop:
                task = source.task = asyncio.ensure_future(self._refresh_source(key))
            if source.entity_ids & self._expired:
                waiting.append(task)
        for task in waiting:
            await asyncio.shield(task)

    def _refuse_if_expired(self: Self, entity_id: str) -> None:
        self._purge()
        if entity_id in self._expired:
            logger.error(f"SAML metadata for {entity_id} is expired, refusing the lookup")
            raise KeyError(entity_id)

    def __iter__(self: Self) -> Iterator[str]:
        return iter(list(self._entities))

    def add_mdq_source(self: Self, source: MDQMetadataSource) -> None:
        self.metadata[source.mdq_url] = source

    @property
    def mdq_sources(self: Self) -> list[MDQMetadataSource]:
        return [source for source in self.metadata.values() if isinstance(source, MDQMetadataSource)]

    def __getitem__(self: Self, entity_id: str) -> pg_metadata.EntityDescriptor:
        try:
            return super().__getitem__(entity_id)
        except KeyError:
            self._refuse_if_expired(entity_id)  # never fall back to MDQ for an entity that expired here
            for source in self.mdq_sources:
                try:
                    return source[entity_id]
                except KeyError:
                    continue
            raise

    def _refuse_if_expired_unknown(self: Self, entity_id: str) -> None:
        try:
            self._refuse_if_expired(entity_id)
        except KeyError:
            raise UnknownSystemEntity(entity_id)

    def _mdq_store(self: Self, entity_id: str) -> MetadataStore:
        """A throwaway store holding only the MDQ entity, so the base class query methods can answer for it"""
        try:
            entity = self[entity_id]
        except KeyError:
            raise UnknownSystemEntity(entity_id)
        store = MetadataStore()
        store._entities[entity_id] = entity
        return store

    def name(self: Self, entity_id: str, langpref: str = "en") -> str:
        self._refuse_if_expired_unknown(entity_id)
        if entity_id in self._entities or not self.mdq_sources:
            return super().name(entity_id, langpref)
        return self._mdq_store(entity_id).name(entity_id, langpref)

    def service(
        self: Self, entity_id: str, descriptor: str, service: str, binding: str | None = None
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
        self._refuse_if_expired_unknown(entity_id)
        if entity_id in self._entities or not self.mdq_sources:
            return super().service(entity_id, descriptor, service, binding)
        return self._mdq_store(entity_id).service(entity_id, descriptor, service, binding)

    def single_sign_on_service(
        self: Self, entity_id: str, binding: str | None = None
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
        return self.service(entity_id, "idpsso_descriptor", "single_sign_on_service", binding)

    # with_descriptor() only lists the local and remote entities, an MDQ source can not be enumerated

    async def prefetch(self: Self, entity_id: str) -> None:
        """Warm the MDQ sources so that later synchronous lookups of entity_id do not block."""
        if entity_id in self._entities:
            return
        for source in self.mdq_sources:
            if await source.prefetch(entity_id) is not None:
                return
