# -*- coding: utf-8 -*-

from unittest import IsolatedAsyncioTestCase

import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError

from auth_server.db.client import BaseDB, MultipleDocumentsReturned
from auth_server.testing import MongoTemporaryInstance

__author__ = 'lundberg'


class TestBaseDB(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.db_client = AsyncIOMotorClient(self.mongo_db.uri, tz_aware=True)
        self.base_db = BaseDB(db_client=self.db_client, db_name='test', collection='test_collection', safe_writes=True)
        # add documents
        self.doc_count = 200
        await self.base_db._coll.insert_many(
            [{f'unique_key': f'value_{i}', 'key': 'test'} for i in range(self.doc_count)]
        )

    async def asyncTearDown(self) -> None:
        await self.base_db._drop_whole_collection()

    async def test_get_all_docs(self):
        docs = [doc async for doc in self.base_db._get_all_docs()]
        assert len(docs) == self.doc_count

    async def test_get_document_by_attr(self):
        doc = await self.base_db._get_document_by_attr(attr='unique_key', value='value_25')
        assert list(doc.keys()) == ['_id', 'unique_key', 'key']
        assert doc['unique_key'] == 'value_25'
        assert doc['key'] == 'test'

        with pytest.raises(MultipleDocumentsReturned):
            await self.base_db._get_document_by_attr(attr='key', value='test')

    async def test_get_documents_by_attr(self):
        docs = [doc async for doc in self.base_db._get_documents_by_attr(attr='unique_key', value='value_25')]
        assert list(docs[0].keys()) == ['_id', 'unique_key', 'key']
        assert docs[0]['unique_key'] == 'value_25'
        assert docs[0]['key'] == 'test'

        docs = [doc async for doc in self.base_db._get_documents_by_attr(attr='key', value='test')]
        assert len(docs) == self.doc_count

    async def def_get_documents_by_filter_fields(self):
        doc_gen = self.base_db._get_documents_by_filter(
            spec={'unique_key': 'value_25'}, fields={'unique_key': 1, 'key': 1}
        )
        docs = [doc async for doc in doc_gen]
        assert docs[0] == {'unique_key': 'value_25', 'key': 'test'}

    async def def_get_documents_by_filter_skip(self):
        doc_gen = self.base_db._get_documents_by_filter(spec={'key': 'test'}, skip=10)
        docs = [doc async for doc in doc_gen]
        assert docs[0]['unique_id'] == 'value_9'

    async def test_get_documents_by_filter_limit(self):
        doc_gen = self.base_db._get_documents_by_filter(spec={'key': 'test'}, limit=10)
        docs = [doc async for doc in doc_gen]
        assert len(docs) == 10

    async def test_db_count(self):
        count = await self.base_db.db_count()
        assert count == self.doc_count

    async def test_db_count_spec(self):
        count = await self.base_db.db_count(spec={'unique_key': 'value_25'})
        assert count == 1

    async def test_db_count_limit(self):
        count = await self.base_db.db_count(spec={'key': 'test'}, limit=1)
        assert count == 1

    async def test_remove_document_spec(self):
        res = await self.base_db.remove_document(spec_or_id={'unique_key': 'value_25'})
        assert res is True
        doc = await self.base_db._get_document_by_attr(attr='unique_key', value='value_25')
        assert doc is None

    async def test_remove_document_id(self):
        doc = await self.base_db._get_document_by_attr(attr='unique_key', value='value_25')
        res = await self.base_db.remove_document(spec_or_id=doc['_id'])
        assert res is True
        doc = await self.base_db._get_document_by_attr(attr='unique_key', value='value_25')
        assert doc is None

    async def test_setup_indexes(self):
        indexes = {
            'unique-unique_key': {'key': [('unique_key', 1)], 'unique': True},
        }
        await self.base_db.setup_indexes(indexes)
        with pytest.raises(DuplicateKeyError):
            await self.base_db._coll.insert_one({'unique_key': 'value_25'})

        # change index
        indexes = {
            'unique_key': {'key': [('unique_key', 1)]},
        }
        await self.base_db.setup_indexes(indexes)
        await self.base_db._coll.insert_one({'unique_key': 'value_25'})
