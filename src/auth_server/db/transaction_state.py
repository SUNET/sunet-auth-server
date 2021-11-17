# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABC
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Type, TypeVar, Union

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from auth_server.db.client import BaseDB, get_mongodb_client
from auth_server.mdq import MDQData
from auth_server.models.gnap import Access, FinishInteraction, GNAPJOSEHeader, GrantRequest, GrantResponse
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import MetadataEntity
from auth_server.utils import get_hex_uuid4

__author__ = 'lundberg'

T = TypeVar('T', bound='TransactionState')


async def get_transaction_state_db() -> Optional[TransactionStateDB]:
    mongo_client = await get_mongodb_client()
    if mongo_client is not None:
        return TransactionStateDB(db_client=mongo_client)
    return None


class TransactionState(BaseModel, ABC):
    transaction_id: str = Field(default_factory=get_hex_uuid4)
    grant_request: GrantRequest
    grant_response: GrantResponse = Field(default_factory=GrantResponse)
    key_reference: Optional[str]
    tls_client_cert: Optional[str]
    jws_header: Optional[GNAPJOSEHeader]
    detached_jws: Optional[str]
    proof_ok: bool = False
    requested_access: List[Union[str, Access]] = Field(default_factory=list)
    saml_assertion: Optional[Mapping]
    interaction_reference: Optional[str]
    user_code: Optional[str]
    continue_reference: Optional[str]
    continue_access_token: Optional[str]
    # meta
    flow_name: str
    flow_step: Optional[str]
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime = Field(default_factory=utc_now)  # default to now, set new expire_at when saving the state

    @classmethod
    def from_dict(cls: Type[T], state: Mapping[str, Any]) -> T:
        return cls(**state)

    def to_dict(self) -> Dict[str, Any]:
        return self.dict(exclude_none=True)


class TestState(TransactionState):
    pass


class ConfigState(TransactionState):
    config_claims: Dict[str, Any] = Field(default_factory=dict)


class MDQState(TransactionState):
    mdq_data: Optional[MDQData]


class TLSFEDState(TransactionState):
    entity: Optional[MetadataEntity]


class TransactionStateDB(BaseDB):
    def __init__(self, db_client: AsyncIOMotorClient):
        super().__init__(db_client=db_client, db_name='auth_server', collection='transaction_states')
        indexes = {
            'auto-discard': {'key': [('expires_at', 1)], 'expireAfterSeconds': 0},
            'unique-transaction-id': {'key': [('transaction_id', 1)], 'unique': True},
            'unique-interaction-reference': {
                'key': [('interaction_reference', 1)],
                'unique': True,
                'partialFilterExpression': {'external_id': {'$type': 'string'}},
            },
            'unique-user-code': {
                'key': [('user_code', 1)],
                'unique': True,
                'partialFilterExpression': {'external_id': {'$type': 'string'}},
            },
        }
        self.setup_indexes(indexes=indexes)

    async def get_document_by_transaction_id(self, transactions_id: str) -> Optional[Mapping[str, Any]]:
        return await self._get_document_by_attr('transaction_id', transactions_id)

    async def get_state_by_transaction_id(self, transactions_id: str) -> Optional[TransactionState]:
        doc = await self._get_document_by_attr('transaction_id', transactions_id)
        if not doc:
            return None
        return TransactionState.from_dict(state=doc)

    async def get_document_by_transaction_reference(self, transaction_reference: str) -> Optional[Mapping[str, Any]]:
        return await self._get_document_by_attr('transaction_reference', transaction_reference)

    async def get_state_by_user_code(self, user_code: str) -> Optional[TransactionState]:
        doc = await self._get_document_by_attr('user_code', user_code)
        if not doc:
            return None
        return TransactionState.from_dict(state=doc)

    async def save(self, state: T, expires_in: timedelta):
        state.expires_at = state.expires_at + expires_in
        test_doc = {'transaction_id': state.transaction_id}
        res = await self._coll.replace_one(test_doc, state.to_dict(), upsert=True)
        return res.acknowledged
