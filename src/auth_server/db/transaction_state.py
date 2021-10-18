# -*- coding: utf-8 -*-
from __future__ import annotations

from abc import ABC
from typing import Any, Dict, List, Mapping, Optional, Type, TypeVar, Union

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from auth_server.db.client import BaseDB, get_mongodb_client
from auth_server.mdq import MDQData
from auth_server.models.gnap import Access, GNAPJOSEHeader, GrantRequest, GrantResponse
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
    flow_name: str
    flow_step: Optional[str]
    transaction_id: str = Field(default_factory=get_hex_uuid4)
    grant_request: GrantRequest
    grant_response: GrantResponse = Field(default_factory=GrantResponse)
    key_reference: Optional[str]
    tls_client_cert: Optional[str]
    jws_header: Optional[GNAPJOSEHeader]
    detached_jws: Optional[str]
    proof_ok: bool = False
    requested_access: List[Union[str, Access]] = Field(default_factory=list)

    @classmethod
    def from_dict(cls: Type[T], state: Mapping[str, Any]) -> T:
        return cls(**state)

    def to_dict(self) -> Dict[str, Any]:
        return self.dict(exclude_unset=True)


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

    async def save(self, state: T):
        test_doc = {'transaction_id': state.transaction_id}
        res = await self._coll.replace_one(test_doc, state.to_dict(), upsert=True)
        return res.acknowledged
