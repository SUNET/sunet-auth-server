# generated by datamodel-codegen:
#   filename:  https://raw.githubusercontent.com/dotse/tls-fed-auth/master/tls-fed-metadata.yaml
#   timestamp: 2021-05-04T15:28:02+00:00

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, List, Optional

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, PositiveInt, StringConstraints

from auth_server.models.jose import JOSEHeader


class TLSFEDJOSEHeader(JOSEHeader):
    iat: datetime
    exp: datetime
    iss: Optional[str] = None


class RegisteredExtensions(str, Enum):
    SAML_SCOPE = "https://kontosynk.internetstiftelsen.se/saml-scope"


class SAMLScopeExtension(BaseModel):
    scope: List[str]


class Extensions(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    saml_scope: Optional[SAMLScopeExtension] = Field(default=None, alias=RegisteredExtensions.SAML_SCOPE.value)


class CertIssuers(BaseModel):
    x509certificate: Optional[str] = Field(None, title="X.509 Certificate (PEM)")


class Alg(str, Enum):
    sha256 = "sha256"


class PinDirective(BaseModel):
    alg: Alg = Field(..., examples=["sha256"], title="Directive name")
    digest: str = Field(
        ...,
        examples=["HiMkrb4phPSP+OvGqmZd6sGvy7AUn4k3XEe8OMBrzt8="],
        title="Directive value (Base64)",
        pattern=r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    )


Tag = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,64}$")]


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="allow")

    description: Optional[str] = Field(None, examples=["SCIM Server 1"], title="Endpoint description")
    tags: Optional[List[Tag]] = Field(
        None,
        description="A list of strings that describe the endpoint's capabilities.\n",
        title="Endpoint tags",
    )
    base_uri: Optional[AnyUrl] = Field(None, examples=["https://scim.example.com"], title="Endpoint base URI")
    pins: List[PinDirective] = Field(..., title="Certificate pin set")


class Entity(BaseModel):
    model_config = ConfigDict(extra="allow")

    entity_id: str = Field(
        ...,
        description="Globally unique identifier for the entity.",
        examples=["https://example.com"],
        title="Entity identifier",
    )
    organization: Optional[str] = Field(
        None,
        description="Name identifying the organization that the entity’s\nmetadata represents.\n",
        examples=["Example Org"],
        title="Name of entity organization",
    )
    issuers: List[CertIssuers] = Field(
        ...,
        description="A list of certificate issuers that are allowed to issue certificates\nfor the entity's endpoints. For each issuer, the issuer's root CA\ncertificate is included in the x509certificate property (PEM-encoded).\n",
        title="Entity certificate issuers",
    )
    servers: Optional[List[Endpoint]] = None
    clients: Optional[List[Endpoint]] = None
    # added after generation
    organization_id: Optional[str] = None
    extensions: Optional[Extensions] = None


class Model(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: str = Field(
        ...,
        examples=["1.0.0"],
        title="Metadata schema version",
        pattern=r"^\d+\.\d+\.\d+$",
    )
    cache_ttl: Optional[PositiveInt] = Field(
        None,
        description="How long (in seconds) to cache metadata.\nEffective maximum TTL is the minimum of HTTP Expire and TTL\n",
        examples=[3600],
        title="Metadata cache TTL",
    )
    entities: List[Entity]
