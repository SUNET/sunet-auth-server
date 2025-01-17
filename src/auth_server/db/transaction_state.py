from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Self, TypeVar

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

from auth_server.db.client import BaseDB, get_motor_client
from auth_server.mdq import MDQData
from auth_server.models.gnap import Access, GrantRequest, GrantResponse, Key, SubjectRequest
from auth_server.saml2 import SessionInfo
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import MetadataEntity
from auth_server.utils import get_hex_uuid4

__author__ = "lundberg"

T = TypeVar("T", bound="TransactionState")


async def get_transaction_state_db() -> TransactionStateDB | None:
    mongo_client = await get_motor_client()
    if mongo_client is not None:
        return await TransactionStateDB.init(db_client=mongo_client)
    return None


class FlowState(str, Enum):
    PROCESSING = "processing"
    PENDING = "pending"
    APPROVED = "approved"
    FINALIZED = "finalized"


class AuthSource(str, Enum):
    INTERACTION = "interaction"
    CONFIG = "config"
    MDQ = "mdq"
    TLSFED = "tlsfed"
    CA = "ca"
    TEST = "test"


class TransactionState(BaseModel, ABC):
    transaction_id: str = Field(default_factory=get_hex_uuid4)
    flow_state: FlowState = Field(default=FlowState.PROCESSING)
    grant_request: GrantRequest
    grant_response: GrantResponse = Field(default_factory=GrantResponse)
    key_reference: str | None = None
    proof_ok: bool = False
    requested_access: list[str | Access] = Field(default_factory=list)
    requested_subject: SubjectRequest = Field(default_factory=SubjectRequest)
    saml_session_info: SessionInfo | None = None
    interaction_reference: str | None = None
    user_code: str | None = None
    continue_reference: str | None = None
    continue_access_token: str | None = None
    # meta
    auth_source: AuthSource | None = None
    flow_name: str
    flow_step: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime = Field(default_factory=utc_now)  # default to now, set new expire_at when saving the state

    @classmethod
    def from_dict(cls: type[T], state: Mapping[str, Any]) -> T:
        return cls(**state)

    def to_dict(self: Self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class TestState(TransactionState):
    auth_source: AuthSource = AuthSource.TEST


class InteractionState(TransactionState):
    auth_source: AuthSource = AuthSource.INTERACTION


class ConfigState(TransactionState):
    auth_source: AuthSource = AuthSource.CONFIG
    config_claims: dict[str, Any] = Field(default_factory=dict)


class MetadataState(TransactionState):
    keys_from_metadata: list[Key] = Field(default_factory=list)


class MDQState(MetadataState):
    auth_source: AuthSource = AuthSource.MDQ
    mdq_data: MDQData | None = None


class TLSFEDState(MetadataState):
    auth_source: AuthSource = AuthSource.TLSFED
    entity: MetadataEntity | None = None


class CAState(TransactionState):
    auth_source: AuthSource = AuthSource.CA
    issuer_common_name: str | None = None
    client_common_name: str | None = None
    client_organization_name: str | None = None
    client_country_code: str | None = None
    organization_id: str | None = None


class TransactionStateDB(BaseDB):
    def __init__(self: Self, db_client: AsyncIOMotorClient) -> None:
        super().__init__(db_client=db_client, db_name="auth_server", collection="transaction_states")

    @classmethod
    async def init(cls: type[TransactionStateDB], db_client: AsyncIOMotorClient) -> TransactionStateDB:
        db = cls(db_client=db_client)
        indexes = {
            "auto-discard": {"key": [("expires_at", 1)], "expireAfterSeconds": 0},
            "unique-transaction-id": {"key": [("transaction_id", 1)], "unique": True},
            "unique-interaction-reference": {
                "key": [("interaction_reference", 1)],
                "unique": True,
                "partialFilterExpression": {"external_id": {"$type": "string"}},
            },
            "unique-user-code": {
                "key": [("user_code", 1)],
                "unique": True,
                "partialFilterExpression": {"external_id": {"$type": "string"}},
            },
        }
        await db.setup_indexes(indexes=indexes)
        return db

    async def get_document_by_transaction_id(self: Self, transaction_id: str) -> Mapping[str, Any] | None:
        return await self._get_document_by_attr("transaction_id", transaction_id)

    async def get_state_by_transaction_id(self: Self, transaction_id: str) -> TransactionState | None:
        doc = await self.get_document_by_transaction_id(transaction_id=transaction_id)
        if not doc:
            return None
        return TransactionState.from_dict(state=doc)

    async def get_document_by_interaction_reference(self: Self, interaction_reference: str) -> Mapping[str, Any] | None:
        return await self._get_document_by_attr("interaction_reference", interaction_reference)

    async def get_document_by_continue_reference(self: Self, continue_reference: str) -> Mapping[str, Any] | None:
        return await self._get_document_by_attr("continue_reference", continue_reference)

    async def get_state_by_user_code(self: Self, user_code: str) -> TransactionState | None:
        doc = await self._get_document_by_attr("user_code", user_code)
        if not doc:
            return None
        return TransactionState.from_dict(state=doc)

    async def remove_state(self: Self, transaction_id: str) -> None:
        await self.remove_document({"transaction_id": transaction_id})

    async def save(self: Self, state: T, expires_in: timedelta) -> bool:
        state.expires_at = state.expires_at + expires_in
        test_doc = {"transaction_id": state.transaction_id}
        res = await self._coll.replace_one(test_doc, state.to_dict(), upsert=True)
        return res.acknowledged
