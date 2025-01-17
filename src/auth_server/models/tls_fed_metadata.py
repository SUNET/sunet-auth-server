# generated by datamodel-codegen:
#   filename:  https://raw.githubusercontent.com/dotse/tls-fed-auth/master/tls-fed-metadata.yaml
#   timestamp: 2021-05-04T15:28:02+00:00

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, PositiveInt, StringConstraints

from auth_server.models.jose import JOSEHeader


class TLSFEDJOSEHeader(JOSEHeader):
    iat: datetime
    exp: datetime
    iss: str | None = None


class RegisteredExtensions(str, Enum):
    SAML_SCOPE = "https://kontosynk.internetstiftelsen.se/saml-scope"


class SAMLScopeExtension(BaseModel):
    scope: list[str]


class Extensions(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    saml_scope: SAMLScopeExtension | None = Field(default=None, alias=RegisteredExtensions.SAML_SCOPE.value)


class CertIssuers(BaseModel):
    x509certificate: str | None = Field(None, title="X.509 Certificate (PEM)")


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

    description: str | None = Field(None, examples=["SCIM Server 1"], title="Endpoint description")
    tags: list[Tag] | None = Field(
        None,
        description="A list of strings that describe the endpoint's capabilities.\n",
        title="Endpoint tags",
    )
    base_uri: AnyUrl | None = Field(None, examples=["https://scim.example.com"], title="Endpoint base URI")
    pins: list[PinDirective] = Field(..., title="Certificate pin set")


class Entity(BaseModel):
    model_config = ConfigDict(extra="allow")

    entity_id: str = Field(
        ...,
        description="Globally unique identifier for the entity.",
        examples=["https://example.com"],
        title="Entity identifier",
    )
    organization: str | None = Field(
        None,
        description="Name identifying the organization that the entity’s\nmetadata represents.\n",
        examples=["Example Org"],
        title="Name of entity organization",
    )
    issuers: list[CertIssuers] = Field(
        ...,
        description="A list of certificate issuers that are allowed to issue certificates\n"
        "for the entity's endpoints. For each issuer, the issuer's root CA\n"
        "certificate is included in the x509certificate property (PEM-encoded).\n",
        title="Entity certificate issuers",
    )
    servers: list[Endpoint] | None = None
    clients: list[Endpoint] | None = None
    # added after generation
    organization_id: str | None = None
    extensions: Extensions | None = None


class Model(BaseModel):
    model_config = ConfigDict(extra="allow")

    version: str = Field(
        ...,
        examples=["1.0.0"],
        title="Metadata schema version",
        pattern=r"^\d+\.\d+\.\d+$",
    )
    cache_ttl: PositiveInt | None = Field(
        description="How long (in seconds) to cache metadata.\n"
        "Effective maximum TTL is the minimum of HTTP Expire and TTL\n",
        examples=[3600],
        title="Metadata cache TTL",
    )
    entities: list[Entity]
