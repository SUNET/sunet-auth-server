# -*- coding: utf-8 -*-
from typing import Optional, List, Union

from pydantic import Extra

from auth_server.models.gnap import Access
from auth_server.models.jose import RegisteredClaims

__author__ = 'lundberg'


class Claims(RegisteredClaims):
    version: int = 1
    source: Optional[str] = None
    origins: Optional[List[str]] = None  # What should we use this for?
    requested_access: Optional[List[Union[str, Access]]] = None


class ConfigClaims(Claims):
    class Config:
        extra = Extra.allow


class MDQClaims(Claims):
    entity_id: str
    scopes: Optional[List[str]] = None


class TLSFEDClaims(MDQClaims):
    organization_id: Optional[str] = None
