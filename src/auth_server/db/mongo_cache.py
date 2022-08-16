# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from collections.abc import MutableMapping
from datetime import timedelta
from logging import getLogger
from typing import Any, Dict, ItemsView, Iterator, KeysView, List, Optional, Tuple, Union, ValuesView

from pymongo import MongoClient, WriteConcern

from auth_server.time_utils import utc_now

logger = getLogger(__name__)


class MongoCacheDB(object):
    def __init__(
        self, db_client: MongoClient, db_name: str, collection: str, expire_after: timedelta, safe_writes: bool = False
    ):

        self._conn = db_client
        self._db_name = db_name
        self._coll_name = collection
        self._db = self._conn[db_name]
        self._coll = self._db[collection]
        self._coll.create_index('lookup_key', unique=True)
        self._coll.create_index('modified_ts', expireAfterSeconds=expire_after.seconds)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=WriteConcern(w='majority'))

    def _get_documents_by_filter(
        self,
        spec: Dict[str, Any],
        fields: Optional[Union[Dict[str, bool], List[str]]] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
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

        for doc in cursor:
            yield doc

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning("{!s} Dropping collection {!r}".format(self, self._coll_name))
        return self._coll.drop()

    def db_count(self, spec: Optional[dict] = None, limit: Optional[int] = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        args: Dict[Any, Any] = {'filter': {}}
        if spec:
            args['filter'] = spec
        if limit:
            args['limit'] = limit
        return self._coll.count_documents(**args)

    def all_items(self, fields: Optional[Union[Dict[str, bool], List[str]]]) -> Iterator[MutableMapping]:
        """
        Return all the items in the database.
        """
        for doc in self._get_documents_by_filter(spec={}, fields=fields):
            yield doc

    def update_item(self, key: str, value: Any) -> None:
        doc = {'lookup_key': key, 'data': value, 'modified_ts': utc_now()}
        self._coll.replace_one({'lookup_key': key}, doc, upsert=True)

    def get_item(self, key: str) -> MutableMapping:
        docs = self._get_documents_by_filter(spec={'lookup_key': key}, fields={'_id': False, 'data': True}, limit=1)
        for doc in docs:
            return doc['data']
        raise KeyError(key)

    def get_items(self) -> Iterator[Tuple[str, Any]]:
        docs = self.all_items(fields={'_id': False, 'lookup_key': True, 'data': True})
        for doc in docs:
            yield doc['lookup_key'], doc['data']

    def get_values(self) -> Iterator[Any]:
        docs = self.all_items(fields={'_id': False, 'data': True})
        for doc in docs:
            yield doc['data']

    def remove_item(self, key: str) -> None:
        self._coll.delete_one(filter={'lookup_key': key})

    def contains_item(self, key: str) -> bool:
        return bool(self.db_count(spec={'lookup_key': key}, limit=1))


class MongoCache(MutableMapping):
    def __init__(self, db_client: MongoClient, db_name: str, collection: str, expire_after: timedelta):
        self._db = MongoCacheDB(
            db_client=db_client, db_name=db_name, collection=collection, expire_after=expire_after, safe_writes=True
        )

    def __iter__(self) -> Iterator[Any]:
        return self._db.get_values()

    def __len__(self) -> int:
        return self._db.db_count()

    def __setitem__(self, key: str, value: Any) -> None:
        self._db.update_item(key, value)

    def __getitem__(self, key: str) -> MutableMapping:
        return self._db.get_item(key)

    def __delitem__(self, key: str) -> None:
        self._db.remove_item(key)

    def __contains__(self, key: Any) -> bool:
        return self._db.contains_item(key)

    def items(self) -> ItemsView[Any, Any]:
        return ItemsView({key: value for key, value in self._db.get_items()})

    def keys(self) -> KeysView[Any]:
        return KeysView({key: value for key, value in self._db.get_items()})

    def values(self) -> ValuesView[Any]:
        return ValuesView({key: value for key, value in self._db.get_items()})
