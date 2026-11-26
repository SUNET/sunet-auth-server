from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from logging import getLogger
from typing import Any, Self

from pygamlastan import metadata as pg_metadata
from pygamlastan.compat.saml2.config import SPConfig
from pygamlastan.compat.saml2.mdstore import MetaDataMDX, MetadataStore
from pygamlastan.compat.saml2.s_utils import UnknownSystemEntity
from pygamlastan.crypto import SamlVerifier

from auth_server.mdq import fetch_mdq_xml

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


class LazyMetadataStore(MetadataStore):
    """
    MetadataStore that resolves entities it does not know from its on-demand (MDQ) sources.

    The compat MetadataStore only knows entities from local and remote documents. All lookups (`[]`, `get()` and `in`)
    that miss are retried against the MDQMetadataSource sources. MDQ entities are not stored in the store itself, the
    source owns their lifetime (ttl, validUntil).
    """

    def add_mdq_source(self: Self, source: MDQMetadataSource) -> None:
        self.metadata[source.mdq_url] = source

    @property
    def mdq_sources(self: Self) -> list[MDQMetadataSource]:
        return [source for source in self.metadata.values() if isinstance(source, MDQMetadataSource)]

    def __getitem__(self: Self, entity_id: str) -> pg_metadata.EntityDescriptor:
        try:
            return super().__getitem__(entity_id)
        except KeyError:
            for source in self.mdq_sources:
                try:
                    return source[entity_id]
                except KeyError:
                    continue
            raise

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
        if entity_id in self._entities or not self.mdq_sources:
            return super().name(entity_id, langpref)
        return self._mdq_store(entity_id).name(entity_id, langpref)

    def service(
        self: Self, entity_id: str, descriptor: str, service: str, binding: str | None = None
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
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


class LazySPConfig(SPConfig):
    """SPConfig that does not guess the only IdP from metadata when entities can also come from an MDQ server"""

    def only_idp(self: Self) -> str | None:
        if not self.idp and isinstance(self.metadata, LazyMetadataStore) and self.metadata.mdq_sources:
            # the MDQ entities can not be enumerated, so "the only IdP in the metadata" is not knowable
            return None
        return super().only_idp()
