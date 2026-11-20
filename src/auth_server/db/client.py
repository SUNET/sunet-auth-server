import asyncio
import logging
import threading
from collections.abc import AsyncGenerator, Mapping
from typing import Any, Self
from weakref import WeakKeyDictionary

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import MongoClient, WriteConcern

from auth_server.config import load_config

__author__ = "lundberg"

logger = logging.getLogger(__name__)


# Motor clients are bound to the event loop they are used in, so there is one client per running loop.
# Value: (mongo uri the client was created for, client). The client references its loop, so the weak key alone
# does not free an entry; entries for closed loops are pruned explicitly in get_motor_client.
_motor_clients: WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[str, AsyncIOMotorClient]] = WeakKeyDictionary()


_motor_clients_lock = threading.Lock()


def _close_client(client: AsyncIOMotorClient) -> None:
    try:
        client.close()
    except Exception as e:  # closing a client whose loop is already gone must not break the caller
        logger.warning(f"failed to close mongo client: {e}")


def clear_motor_client_cache() -> None:
    """Close all cached clients and forget them. Sync so that it can be used from test helpers."""
    with _motor_clients_lock:
        clients = [client for _, client in _motor_clients.values()]
        _motor_clients.clear()
    for client in clients:
        _close_client(client)


# Number of running lifespans per loop. Lifespans only close the client of their own loop, and only the last
# one on a loop does so, so overlapping lifespans do not close each other's client.
_lifespan_users: WeakKeyDictionary[asyncio.AbstractEventLoop, int] = WeakKeyDictionary()


def acquire_motor_lifespan() -> None:
    """Register an app lifespan running on the current event loop."""
    loop = asyncio.get_running_loop()
    with _motor_clients_lock:
        _lifespan_users[loop] = _lifespan_users.get(loop, 0) + 1


def release_motor_lifespan() -> None:
    """Unregister an app lifespan; close the current loop's client when it was the last one on this loop."""
    loop = asyncio.get_running_loop()
    client: AsyncIOMotorClient | None = None
    with _motor_clients_lock:
        users = _lifespan_users.get(loop, 0) - 1
        if users > 0:
            _lifespan_users[loop] = users
            return
        _lifespan_users.pop(loop, None)
        cached = _motor_clients.pop(loop, None)
        if cached is not None:
            client = cached[1]
    if client is not None:
        _close_client(client)


async def get_motor_client() -> AsyncIOMotorClient | None:
    """Return the motor client for the running event loop and configured mongo uri, creating it if needed."""
    config = load_config()
    if config.mongo_uri is None:
        return None
    loop = asyncio.get_running_loop()
    uri = config.mongo_uri
    to_close: list[AsyncIOMotorClient] = []
    try:
        with _motor_clients_lock:
            # drop clients of loops that have been closed (a new loop per request, as the test client does)
            closed = [
                (old_loop, old_client) for old_loop, (_, old_client) in _motor_clients.items() if old_loop.is_closed()
            ]
            for old_loop, old_client in closed:
                del _motor_clients[old_loop]
                to_close.append(old_client)
            cached = _motor_clients.get(loop)
            if cached is not None and cached[0] == uri:
                return cached[1]
        # Construct outside the lock: an SRV uri does blocking DNS resolution that must not stall other loops.
        # If it raises, the current cache entry stays in place.
        client = AsyncIOMotorClient(uri, tz_aware=True)
        with _motor_clients_lock:
            current = _motor_clients.get(loop)
            if current is not None and current[0] == uri:
                # lost a race for this loop; use the published client and discard ours
                to_close.append(client)
                return current[1]
            if current is not None:
                to_close.append(current[1])
            _motor_clients[loop] = (uri, client)
        return client
    finally:
        # also runs when the constructor raised, so clients already removed from the cache are not leaked
        for old_client in to_close:
            _close_client(old_client)


async def get_mongo_client() -> MongoClient | None:
    config = load_config()
    if config.mongo_uri is None:
        return None
    return MongoClient(config.mongo_uri, tz_aware=True)


class DBError(Exception):
    pass


class MultipleDocumentsReturned(DBError):
    pass


class BaseDB:
    """Base class for common db operations"""

    def __init__(
        self: Self, db_client: AsyncIOMotorClient, db_name: str, collection: str, safe_writes: bool = False
    ) -> None:
        self._conn = db_client
        self._db_name = db_name
        self._coll_name = collection
        self._db = self._conn[db_name]
        self._coll = self._db[collection]
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=WriteConcern(w="majority"))

    def __repr__(self: Self) -> str:
        return f"<AsyncBaseDB {self.__class__.__name__}: {self._db_name}.{self._coll_name}>"

    __str__ = __repr__

    async def _drop_whole_collection(self: Self) -> None:
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning(f"{self!s} Dropping collection {self._coll_name!r}")
        return await self._coll.drop()

    async def _get_all_docs(self: Self) -> AsyncGenerator[Mapping, None]:
        """
        Return all the documents in the database.
        """
        async for doc in self._get_documents_by_filter(spec={}):
            yield doc

    async def _get_document_by_attr(self: Self, attr: str, value: str) -> Mapping | None:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: document dict or None
        """
        if value is None:
            raise DBError(f"Missing value to filter docs by {attr}")

        docs = await self._coll.find({attr: value}).to_list(length=2)  # Try to get two docs for multiple check
        doc_count = len(docs)
        if doc_count == 0:
            return None
        elif doc_count > 1:
            raise MultipleDocumentsReturned(f"Multiple matching documents for {attr}={repr(value)}")
        return docs[0]

    async def _get_documents_by_attr(self: Self, attr: str, value: str) -> AsyncGenerator[Mapping, None]:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A document dict
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        async for doc in self._get_documents_by_filter(spec={attr: value}):
            yield doc

    async def _get_documents_by_filter(
        self: Self,
        spec: dict[str, Any],
        fields: dict[str, bool] | list[str] | None = None,
        skip: int | None = None,
        limit: int | None = None,
    ) -> AsyncGenerator[Mapping, None]:
        """
        Locate documents in the db using a custom search filter.

        :param spec: the search filter
        :param fields: the fields to include/exclude in the search result
        :param skip: Number of documents to skip before returning result
        :param limit: Limit documents returned to this number
        """
        if fields is not None:
            cursor = self._coll.find(filter=spec, projection=fields)
        else:
            cursor = self._coll.find(filter=spec)

        if skip is not None:
            cursor = cursor.skip(skip=skip)
        if limit is not None:
            cursor = cursor.limit(limit=limit)

        async for doc in cursor:
            yield doc

    async def db_count(self: Self, spec: dict | None = None, limit: int | None = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        args: dict[Any, Any] = {"filter": {}}
        if spec:
            args["filter"] = spec
        if limit:
            args["limit"] = limit
        return await self._coll.count_documents(**args)

    async def remove_document(self: Self, spec_or_id: dict | ObjectId) -> bool:
        """
        Remove a document in the db given the _id or dict spec.

        :param spec_or_id: spec or document id (_id)
        """
        if isinstance(spec_or_id, ObjectId):
            spec_or_id = {"_id": spec_or_id}
        result = await self._coll.delete_one(spec_or_id)
        return result.acknowledged

    async def setup_indexes(self: Self, indexes: dict[str, Any]) -> None:
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }  # noqa: ERA001
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ["_id_"]  # _id_ index can not be deleted from a mongo collection
        current_indexes = await self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                await self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop("key")
                params["name"] = name
                await self._coll.create_index(key, **params)
