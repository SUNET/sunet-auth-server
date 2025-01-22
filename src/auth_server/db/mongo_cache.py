__author__ = "lundberg"

from collections.abc import ItemsView, Iterator, KeysView, MutableMapping, ValuesView
from datetime import timedelta
from logging import getLogger
from typing import Any, Self

from pymongo import MongoClient, WriteConcern

from auth_server.time_utils import utc_now

logger = getLogger(__name__)


class CacheWriteException(Exception):
    pass


class MongoCacheDB:
    def __init__(
        self: Self,
        db_client: MongoClient,
        db_name: str,
        collection: str,
        expire_after: timedelta,
        safe_writes: bool = False,
    ) -> None:
        self._conn = db_client
        self._db_name = db_name
        self._coll_name = collection
        self._db = self._conn[db_name]
        self._coll = self._db[collection]
        self._coll.create_index("lookup_key", unique=True)
        self._coll.create_index("modified_ts", expireAfterSeconds=int(expire_after.total_seconds()))
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=WriteConcern(w="majority"))

    def _get_documents_by_filter(
        self: Self,
        spec: dict[str, Any],
        fields: dict[str, bool] | list[str] | None = None,
        skip: int | None = None,
        limit: int | None = None,
    ) -> Iterator[MutableMapping]:
        """
        Locate documents in the db using a custom search filter.

        :param spec: the search filter
        :param fields: the fields to include/exclude in the search result
        :param skip: Number of documents to skip before returning result
        :param limit: Limit documents returned to this number
        :return: A list of documents
        """
        if fields is not None:
            cursor = self._coll.find(spec, fields)
        else:
            cursor = self._coll.find(spec)

        if skip is not None:
            cursor = cursor.skip(skip=skip)
        if limit is not None:
            cursor = cursor.limit(limit=limit)

        yield from cursor

    def _drop_whole_collection(self: Self) -> None:
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning(f"{self!s} Dropping collection {self._coll_name!r}")
        return self._coll.drop()

    def db_count(self: Self, spec: dict | None = None, limit: int | None = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        args: dict[Any, Any] = {"filter": {}}
        if spec:
            args["filter"] = spec
        if limit:
            args["limit"] = limit
        return self._coll.count_documents(**args)

    def all_items(self: Self, fields: dict[str, bool] | list[str] | None) -> Iterator[MutableMapping]:
        """
        Return all the items in the database.
        """
        yield from self._get_documents_by_filter(spec={}, fields=fields)

    def update_item(self: Self, key: str, value: str | int | bool | list | dict) -> None:
        doc = {"lookup_key": key, "data": value, "modified_ts": utc_now()}
        res = self._coll.replace_one({"lookup_key": key}, doc, upsert=True)
        if not res.acknowledged or (res.matched_count != res.modified_count):
            raise CacheWriteException(f"Failed to UPDATE item {key} in collection {self._coll.name}")

    def get_item(self: Self, key: str) -> str | int | bool | dict | list:
        docs = self._get_documents_by_filter(spec={"lookup_key": key}, fields={"_id": False, "data": True}, limit=1)
        for doc in docs:
            return doc["data"]
        raise KeyError(key)

    def get_items(self: Self) -> Iterator[tuple[str, Any]]:
        docs = self.all_items(fields={"_id": False, "lookup_key": True, "data": True})
        for doc in docs:
            yield doc["lookup_key"], doc["data"]

    def get_values(self: Self) -> Iterator[Any]:
        docs = self.all_items(fields={"_id": False, "data": True})
        for doc in docs:
            yield doc["data"]

    def remove_item(self: Self, key: str) -> None:
        res = self._coll.delete_one(filter={"lookup_key": key})
        if not res.acknowledged or (res.deleted_count != 1):
            raise CacheWriteException(f"Failed to DELETE item {key} in collection {self._coll.name}")

    def contains_item(self: Self, key: str) -> bool:
        return bool(self.db_count(spec={"lookup_key": key}, limit=1))


class MongoCache(MutableMapping):
    def __init__(self: Self, db_client: MongoClient, db_name: str, collection: str, expire_after: timedelta) -> None:
        self._db = MongoCacheDB(
            db_client=db_client, db_name=db_name, collection=collection, expire_after=expire_after, safe_writes=True
        )

    def __iter__(self: Self) -> Iterator[Any]:
        return self._db.get_values()

    def __len__(self: Self) -> int:
        return self._db.db_count()

    def __setitem__(self: Self, key: str, value: str | int | bool | dict | list) -> None:
        self._db.update_item(key, value)

    def __getitem__(self: Self, key: str) -> str | int | bool | dict | list:
        return self._db.get_item(key)

    def __delitem__(self: Self, key: str) -> None:
        self._db.remove_item(key)

    def __contains__(self: Self, key: str) -> bool:  # type: ignore[override]
        return self._db.contains_item(key)

    def items(self: Self) -> ItemsView[Any, Any]:
        return ItemsView({key: value for key, value in self._db.get_items()})

    def keys(self: Self) -> KeysView[Any]:
        return KeysView({key: value for key, value in self._db.get_items()})

    def values(self: Self) -> ValuesView[Any]:
        return ValuesView({key: value for key, value in self._db.get_items()})
