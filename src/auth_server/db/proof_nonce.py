import logging
from collections import deque
from datetime import timedelta
from time import monotonic
from typing import Self

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import BulkWriteError

from auth_server.config import load_config
from auth_server.db.client import BaseDB, get_motor_client
from auth_server.time_utils import utc_now

__author__ = "lundberg"

logger = logging.getLogger(__name__)

DUPLICATE_KEY_ERROR_CODE = 11000


class ProofNonceDB(BaseDB):
    """Remembers signature nonces for as long as a signature carrying them could still be accepted."""

    def __init__(self: Self, db_client: AsyncIOMotorClient, ttl: timedelta) -> None:
        super().__init__(db_client=db_client, db_name="auth_server", collection="proof_nonces")
        self.ttl = ttl

    @classmethod
    async def init(cls: type["ProofNonceDB"], db_client: AsyncIOMotorClient, ttl: timedelta) -> "ProofNonceDB":
        db = cls(db_client=db_client, ttl=ttl)
        indexes = {
            # the ttl is part of the name so that a changed config replaces the index
            f"auto-discard-{int(ttl.total_seconds())}": {
                "key": [("created_at", 1)],
                "expireAfterSeconds": int(ttl.total_seconds()),
            },
            "unique-key-fingerprint-nonce": {"key": [("key_fingerprint", 1), ("nonce", 1)], "unique": True},
        }
        # leftovers from before nonces were scoped by key fingerprint would all collide in the unique index
        await db._coll.delete_many({"key_fingerprint": {"$exists": False}})
        await db.setup_indexes(indexes=indexes)
        return db

    async def check_and_store(self: Self, key_fingerprint: str, nonce: str) -> bool:
        """Store the nonce. Returns False if the nonce has been seen before for this key."""
        return await self.check_and_store_all(key_fingerprint=key_fingerprint, nonces=[nonce])

    async def check_and_store_all(self: Self, key_fingerprint: str, nonces: list[str]) -> bool:
        """
        Store all the nonces. Returns False if any of them has been seen before for this key.

        The key fingerprint identifies the key material and proof parameters, not the client chosen kid.

        The nonces are inserted in one unordered bulk write. If some of them were already stored the others are still
        inserted and kept: the caller rejects the request, and a retry of the same request must stay rejected.
        """
        now = utc_now()
        documents = [
            {"key_fingerprint": key_fingerprint, "nonce": nonce, "created_at": now}
            for nonce in dict.fromkeys(nonces)  # the same nonce twice in one request is one nonce
        ]
        if not documents:
            return True
        try:
            await self._coll.insert_many(documents, ordered=False)
        except BulkWriteError as e:
            if all(error.get("code") == DUPLICATE_KEY_ERROR_CODE for error in e.details.get("writeErrors", [])):
                return False
            raise
        return True


class InMemoryProofNonceStore:
    """Single process fallback used when there is no database. Does not protect multiple workers/instances."""

    def __init__(self: Self, ttl: timedelta) -> None:
        self.ttl = ttl
        self._seen: dict[tuple[str, str], float] = {}
        # the ttl is the same for every nonce so they expire in the order they were stored
        self._expiry_queue: deque[tuple[float, tuple[str, str]]] = deque()

    async def check_and_store(self: Self, key_fingerprint: str, nonce: str) -> bool:
        return await self.check_and_store_all(key_fingerprint=key_fingerprint, nonces=[nonce])

    async def check_and_store_all(self: Self, key_fingerprint: str, nonces: list[str]) -> bool:
        """Store all the nonces, or none of them if any has been seen before for this key."""
        now = monotonic()
        while self._expiry_queue and self._expiry_queue[0][0] <= now:
            _, expired = self._expiry_queue.popleft()
            self._seen.pop(expired, None)
        keys = [(key_fingerprint, nonce) for nonce in dict.fromkeys(nonces)]
        if any(key in self._seen for key in keys):
            return False
        expires = now + self.ttl.total_seconds()
        for key in keys:
            self._seen[key] = expires
            self._expiry_queue.append((expires, key))
        return True


_in_memory_store: InMemoryProofNonceStore | None = None
# (mongo uri, ttl in seconds) for which the indexes are known to be in place
_indexes_ready: set[tuple[str, int]] = set()


def clear_proof_nonce_cache() -> None:
    """Forget cached state. For use in tests that drop the collection or change the configuration."""
    global _in_memory_store  # noqa: PLW0603
    _in_memory_store = None
    _indexes_ready.clear()


async def get_proof_nonce_store(ttl: timedelta) -> ProofNonceDB | InMemoryProofNonceStore:
    global _in_memory_store  # noqa: PLW0603
    config = load_config()
    mongo_client = await get_motor_client()
    if mongo_client is not None and config.mongo_uri is not None:
        ready_key = (config.mongo_uri, int(ttl.total_seconds()))
        if ready_key in _indexes_ready:
            return ProofNonceDB(db_client=mongo_client, ttl=ttl)
        db = await ProofNonceDB.init(db_client=mongo_client, ttl=ttl)
        _indexes_ready.add(ready_key)
        return db
    if _in_memory_store is None or _in_memory_store.ttl != ttl:
        logger.warning("no database configured, httpsig nonces are only remembered in this process")
        _in_memory_store = InMemoryProofNonceStore(ttl=ttl)
    return _in_memory_store
