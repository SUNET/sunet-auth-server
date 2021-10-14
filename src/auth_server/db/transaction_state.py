# -*- coding: utf-8 -*-
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from auth_server.mdq import MDQData
from auth_server.models.gnap import Access, GrantRequest, GrantResponse
from auth_server.tls_fed_auth import MetadataEntity

__author__ = 'lundberg'


class TransactionState(BaseModel):
    grant_request: GrantRequest
    grant_response: GrantResponse = Field(default_factory=GrantResponse)
    tls_client_cert: Optional[str]
    detached_jws: Optional[str]
    proof_ok: bool = False
    requested_access: List[Union[str, Access]] = Field(default_factory=list)


class ConfigState(TransactionState):
    config_claims: Dict[str, Any] = Field(default_factory=dict)


class MDQState(TransactionState):
    mdq_data: Optional[MDQData]


class TLSFEDState(TransactionState):
    entity: Optional[MetadataEntity]
