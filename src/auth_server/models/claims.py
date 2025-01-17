from pydantic import ConfigDict

from auth_server.models.gnap import Access
from auth_server.models.jose import RegisteredClaims

__author__ = "lundberg"


class Claims(RegisteredClaims):
    version: int = 1
    auth_source: str
    source: str | None = None
    origins: list[str] | None = None  # What should we use this for?
    requested_access: list[str | Access] | None = None


class ConfigClaims(Claims):
    model_config = ConfigDict(extra="allow")


class CAClaims(Claims):
    common_name: str
    organization_name: str | None = None
    country_code: str | None = None
    organization_id: str | None = None


class MDQClaims(Claims):
    entity_id: str
    scopes: list[str] | None = None


class TLSFEDClaims(MDQClaims):
    organization_id: str | None = None


class SAMLAssertionClaims(Claims):
    saml_issuer: str | None = None
    saml_assurance: list[str] | None = None
    saml_entitlement: list[str] | None = None
    saml_eppn: str | None = None
    saml_unique_id: str | None = None
    saml_targeted_id: str | None = None
