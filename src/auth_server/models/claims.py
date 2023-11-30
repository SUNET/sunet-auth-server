# -*- coding: utf-8 -*-
from typing import List, Optional, Union

from pydantic import ConfigDict

from auth_server.models.gnap import Access
from auth_server.models.jose import RegisteredClaims

__author__ = "lundberg"


class Claims(RegisteredClaims):
    version: int = 1
    auth_source: str
    source: Optional[str] = None
    origins: Optional[List[str]] = None  # What should we use this for?
    requested_access: Optional[List[Union[str, Access]]] = None


class ConfigClaims(Claims):
    model_config = ConfigDict(extra="allow")


class CAClaims(Claims):
    common_name: str
    organization_id: Optional[str] = None


class MDQClaims(Claims):
    entity_id: str
    scopes: Optional[List[str]] = None


class TLSFEDClaims(MDQClaims):
    organization_id: Optional[str] = None


class SAMLAssertionClaims(Claims):
    saml_issuer: Optional[str] = None
    saml_assurance: Optional[list[str]] = None
    saml_entitlement: Optional[list[str]] = None
    saml_eppn: Optional[str] = None
    saml_unique_id: Optional[str] = None
    saml_targeted_id: Optional[str] = None
