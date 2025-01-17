from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from auth_server.models.jose import (
    ECJWK,
    RSAJWK,
    JOSEHeader,
    SupportedAlgorithms,
    SupportedHTTPMethods,
    SupportedJWSType,
    SupportedJWSTypeLegacy,
    SymmetricJWK,
)

__author__ = "lundberg"


# Data models for GNAP
# https://datatracker.ietf.org/doc/html/draft-ietf-gnap-core-protocol


class GnapBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class ProofMethod(str, Enum):
    HTTPSIG = "httpsig"
    MTLS = "mtls"
    JWSD = "jwsd"
    JWS = "jws"
    TEST = "test"


class Proof(GnapBaseModel):
    method: ProofMethod


class Key(GnapBaseModel):
    proof: Proof
    jwk: ECJWK | RSAJWK | SymmetricJWK | None = None
    cert: str | None = None
    cert_S256: str | None = Field(default=None, alias="cert#S256")

    @field_validator("proof", mode="before")
    @classmethod
    def expand_proof(cls: "Key", v: str | dict[str, Any]) -> dict[str, Any]:
        # If additional parameters are not required or used for a specific method,
        # the method MAY be passed as a string instead of an object.
        if isinstance(v, str):
            return {"method": v}
        return v


class Access(GnapBaseModel):
    # The value of the "type" field is under the control of the AS.  This
    # field MUST be compared using an exact byte match of the string value
    # against known types by the AS.  The AS MUST ensure that there is no
    # collision between different authorization data types that it
    # supports.  The AS MUST NOT do any collation or normalization of data
    # types during comparison.  It is RECOMMENDED that designers of
    # general-purpose APIs use a URI for this field to avoid collisions
    # between multiple API types protected by a single AS.
    type: str
    # The types of actions the client instance will take at the RS as an
    # array of strings.  For example, a client instance asking for a
    # combination of "read" and "write" access.
    actions: list[str] | None = None
    # The location of the RS as an array of strings. These strings are
    # typically URIs identifying the location of the RS.
    locations: list[str] | None = None
    # The kinds of data available to the client instance at the RS's API
    # as an array of strings.  For example, a client instance asking for
    # access to raw "image" data and "metadata" at a photograph API.
    datatypes: list[str] | None = None
    # A string identifier indicating a specific resource at the RS. For
    # example, a patient identifier for a medical API or a bank account
    # number for a financial API.
    identifier: str | None = None
    # The types or levels of privilege being requested at the resource.
    # For example, a client instance asking for administrative level
    # access, or access when the resource owner is no longer online.
    privileges: list[str] | None = None
    # Sunet addition for requesting access to a specified scope
    scope: str | None = None


class AccessTokenFlags(str, Enum):
    BEARER = "bearer"
    DURABLE = "durable"


class AccessTokenRequest(GnapBaseModel):
    access: list[str | Access] | None = None
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: str | None = None
    flags: list[AccessTokenFlags] | None = None


class SubjectIdentifierFormat(str, Enum):
    ACCOUNT = "account"
    ALIASES = "aliases"
    DID = "did"
    EMAIL = "email"
    ISS_SUB = "iss_sub"
    OPAQUE = "opaque"
    PHONE_NUMBER = "phone_number"


class SubjectAssertionFormat(str, Enum):
    ID_TOKEN = "id_token"
    SAML2 = "saml2"


class SubjectRequest(GnapBaseModel):
    sub_id_formats: list[SubjectIdentifierFormat] | None = None
    assertion_formats: list[SubjectAssertionFormat] | None = None
    authentication_context: list[str] | None = None


class Display(GnapBaseModel):
    name: str | None = None
    uri: str | None = None
    logo_uri: str | None = None


class Client(GnapBaseModel):
    key: str | Key
    class_id: str | None = None
    display: Display | None = None


class SubjectIdentifier(GnapBaseModel):
    # sub_ids should contain objects as {"format": "opaque", "id": "J2G8G8O4AZ"} or
    # {"format": "email", "email": "user@example.com"} #  noqa: ERA001
    # see ietf-secevent-subject-identifiers
    format: SubjectIdentifierFormat
    model_config = ConfigDict(extra="allow")


class SubjectAssertion(GnapBaseModel):
    format: SubjectAssertionFormat
    value: str


class User(GnapBaseModel):
    sub_ids: list[SubjectIdentifier] | None = None
    # An object containing assertions as values keyed on the assertion type.
    # Possible keys include "id_token" for an [OIDC] ID Token and "saml2" for a SAML 2 assertion.
    assertions: list[SubjectAssertion] | None = None


class TokenManagementInfo(GnapBaseModel):
    # TODO:
    #    uri (string):  The URI of the token management API for this access
    #       token.  This URI MUST be an absolute URI.  This URI MUST NOT
    #       include the value of the access token being managed or the value
    #       of the access token used to protect the URI.  This URI SHOULD be
    #       different for each access token issued in a request.  REQUIRED.
    #    access_token (object):  A unique access token for continuing the
    #       request, called the "token management access token".  The value of
    #       this property MUST be an object in the format specified in
    #       Section 3.2.1.  This access token MUST be bound to the client
    #       instance's key used in the request (or its most recent rotation)
    #       and MUST NOT be a bearer token.  As a consequence, the flags array
    #       of this access token MUST NOT contain the string bearer, and the
    #       key field MUST be omitted.  This access token MUST NOT have a
    #       manage field.  This access token MUST NOT have the same value as
    #       the token it is managing.  The client instance MUST present the
    #       continuation access token in all requests to the continuation URI
    #       as described in Section 7.2.  REQUIRED.
    uri: str | None = None
    access_token: Any | None = None


class StartInteractionMethod(str, Enum):
    REDIRECT = "redirect"
    APP = "app"
    USER_CODE = "user_code"  # for use with a stable URI
    USER_CODE_URI = "user_code_uri"  # for use with a dynamic URI


class FinishInteractionMethod(str, Enum):
    REDIRECT = "redirect"
    PUSH = "push"


class HashMethod(str, Enum):
    # Hash names has to match https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
    SHA_256 = "sha-256"
    SHA_512 = "sha-512"
    SHA3_256 = "sha3-256"
    SHA3_384 = "sha3-384"
    SHA3_512 = "sha3-512"


class FinishInteraction(GnapBaseModel):
    method: FinishInteractionMethod
    uri: str
    nonce: str
    hash_method: HashMethod | None = None


class Hints(GnapBaseModel):
    ui_locales: list[str] | None = None


class InteractionRequest(GnapBaseModel):
    start: list[StartInteractionMethod]
    finish: FinishInteraction | None = None
    hints: Hints | None = None


class GrantRequest(GnapBaseModel):
    access_token: AccessTokenRequest | list[AccessTokenRequest]
    subject: SubjectRequest | None = None
    client: str | Client
    user: str | User | None = None
    interact: InteractionRequest | None = None


class ContinueAccessToken(GnapBaseModel):
    bound: bool = True
    value: str


class Continue(GnapBaseModel):
    uri: str
    wait: int | None = None
    access_token: ContinueAccessToken


class UserCodeURI(GnapBaseModel):
    code: str
    uri: str


class InteractionResponse(GnapBaseModel):
    redirect: str | None = None
    app: str | None = None
    user_code: str | None = None
    user_code_uri: UserCodeURI | None = None
    finish: str | None = None
    expires_in: int | None = None


class AccessTokenResponse(GnapBaseModel):
    value: str
    label: str | None = None
    manage: TokenManagementInfo | None = None
    access: list[str | Access] | None = None
    expires_in: int | None = Field(default=None, description="seconds until expiry")
    key: str | Key | None = None
    flags: list[AccessTokenFlags] | None = None


class SubjectResponse(GnapBaseModel):
    sub_ids: list[SubjectIdentifier] | None = None
    assertions: list[SubjectAssertion] | None = None
    updated_at: datetime | None = Field(default=None, description="ISO8610 date string")


class ErrorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_INTERACTION = "invalid_interaction"
    INVALID_FLAG = "invalid_flag"
    INVALID_ROTATION = "invalid_rotation"
    KEY_ROTATION_NOT_SUPPORTED = "key_rotation_not_supported"
    INVALID_CONTINUATION = "invalid_continuation"
    USER_DENIED = "user_denied"
    REQUEST_DENIED = "request_denied"
    UNKNOWN_USER = "unknown_user"
    UNKNOWN_INTERACTION = "unknown_interaction"
    TOO_FAST = "too_fast"
    TOO_MANY_ATTEMPTS = "too_many_attempts"


# TODO: Change FastApi HTTPException responses to ErrorResponse
class ErrorResponse(BaseModel):
    code: ErrorCode
    error_description: str | None = None
    continue_: Continue | None = Field(default=None, alias="continue")


class ContinueRequest(GnapBaseModel):
    interact_ref: str | None = None


class GrantResponse(GnapBaseModel):
    continue_: Continue | None = Field(default=None, alias="continue")
    access_token: AccessTokenResponse | None = None
    interact: InteractionResponse | None = None
    subject: SubjectResponse | None = None
    instance_id: str | None = None
    user_handle: str | None = None


class GNAPJOSEHeader(JOSEHeader):
    kid: str
    alg: SupportedAlgorithms
    typ: SupportedJWSType | SupportedJWSTypeLegacy
    htm: SupportedHTTPMethods
    # The HTTP URI used for this request, including all path and query components.
    uri: str
    # A timestamp of when the signature was created
    created: datetime
    # When a request is bound to an access token, the access token hash value. The value MUST be the result of
    # Base64url encoding (with no padding) the SHA-256 digest of the ASCII encoding of the associated access
    # token's value.  REQUIRED if the request protects an access token.
    ath: str | None = None
