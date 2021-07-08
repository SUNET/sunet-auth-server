# -*- coding: utf-8 -*-
import logging
from typing import Any, AsyncGenerator, Dict, Mapping, Optional, Union

from async_lru import alru_cache
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import WriteConcern

from auth_server.config import ConfigurationError, load_config

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


@alru_cache
async def get_mongodb_client():
    config = load_config()
    if config.mongo_uri is None:
        raise ConfigurationError('mongo_uri not set')
    return AsyncIOMotorClient(config.mongo_uri, tz_aware=True)


class DBError(Exception):
    pass


class MultipleDocumentsReturned(DBError):
    pass


class BaseDB(object):
    """ Base class for common db operations """

    def __init__(self, db_client: AsyncIOMotorClient, db_name: str, collection: str, safe_writes: bool = False):

        self._conn = db_client
        self._db_name = db_name
        self._coll_name = collection
        self._db = self._conn[db_name]
        self._coll = self._db[collection]
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=WriteConcern(w='majority'))

    def __repr__(self):
        return f'<AsyncMongoDB {self.__class__.__name__}: {self._db_name}.{self._coll_name}>'

    __str__ = __repr__

    async def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning("{!s} Dropping collection {!r}".format(self, self._coll_name))
        return await self._coll.drop()

    async def _get_all_docs(self) -> AsyncGenerator[Mapping, None]:
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        :rtype:
        """
        async for doc in self._get_documents_by_filter(spec={}):
            yield doc

    async def _get_document_by_attr(self, attr: str, value: str) -> Optional[Mapping]:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: document dict or None
        """
        if value is None:
            raise DBError(f'Missing value to filter docs by {attr}')

        docs = await self._coll.find({attr: value}).to_list(length=2)  # Try to get two docs for multiple check
        doc_count = len(docs)
        if doc_count == 0:
            return None
        elif doc_count > 1:
            raise MultipleDocumentsReturned(f'Multiple matching documents for {attr}={repr(value)}')
        return docs[0]

    async def _get_documents_by_attr(self, attr: str, value: str) -> AsyncGenerator[Mapping, None]:
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
        self, spec: dict, fields: Optional[dict] = None, skip: Optional[int] = None, limit: Optional[int] = None,
    ) -> AsyncGenerator[Mapping, None]:
        """
        Locate documents in the db using a custom search filter.

        :param spec: the search filter
        :param fields: the fields to return in the search result
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

        async for doc in cursor:
            yield doc

    async def db_count(self, spec: Optional[dict] = None, limit: Optional[int] = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        args: Dict[Any, Any] = {'filter': {}}
        if spec:
            args['filter'] = spec
        if limit:
            args['limit'] = limit
        return await self._coll.count_documents(**args)

    async def remove_document(self, spec_or_id: Union[dict, ObjectId]) -> bool:
        """
        Remove a document in the db given the _id or dict spec.

        :param spec_or_id: spec or document id (_id)
        """
        if isinstance(spec_or_id, ObjectId):
            spec_or_id = {'_id': spec_or_id}
        result = await self._coll.delete_one(spec_or_id)
        return result.acknowledged

    async def setup_indexes(self, indexes: Dict[str, Any]):
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ['_id_']  # _id_ index can not be deleted from a mongo collection
        current_indexes = await self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                await self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop('key')
                params['name'] = name
                await self._coll.create_index(key, **params)

    async def close(self):
        self._db.close()
