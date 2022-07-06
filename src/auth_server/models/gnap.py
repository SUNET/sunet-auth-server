# -*- coding: utf-8 -*-
from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

from pydantic import AnyUrl, BaseModel, Extra, Field

from auth_server.models.jose import (
    ECJWK,
    RSAJWK,
    JOSEHeader,
    SupportedAlgorithms,
    SupportedHTTPMethods,
    SupportedJWSType,
    SymmetricJWK,
)

__author__ = 'lundberg'


# Data models for GNAP
# https://datatracker.ietf.org/doc/html/draft-ietf-gnap-core-protocol


class GnapBaseModel(BaseModel):
    class Config:
        allow_population_by_field_name = True


class Proof(str, Enum):
    DPOP = 'dpop'
    HTTPSIGN = 'httpsign'
    JWSD = 'jwsd'
    JWS = 'jws'
    MTLS = 'mtls'
    OAUTHPOP = 'oauthpop'
    TEST = 'test'


class Key(GnapBaseModel):
    proof: Proof
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]] = None
    cert: Optional[str] = None
    cert_S256: Optional[str] = Field(default=None, alias='cert#S256')


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
    actions: Optional[List[str]] = None
    # The location of the RS as an array of strings. These strings are
    # typically URIs identifying the location of the RS.
    locations: Optional[List[str]] = None
    # The kinds of data available to the client instance at the RS's API
    # as an array of strings.  For example, a client instance asking for
    # access to raw "image" data and "metadata" at a photograph API.
    datatypes: Optional[List[str]] = None
    # A string identifier indicating a specific resource at the RS. For
    # example, a patient identifier for a medical API or a bank account
    # number for a financial API.
    identifier: Optional[str] = None
    # The types or levels of privilege being requested at the resource.
    # For example, a client instance asking for administrative level
    # access, or access when the resource owner is no longer online.
    privileges: Optional[List[str]] = None
    # Sunet addition for requesting access to a specified scope
    scope: Optional[str] = None


class AccessTokenFlags(str, Enum):
    BEARER = 'bearer'
    DURABLE = 'durable'
    SPLIT = 'split'


class AccessTokenRequest(GnapBaseModel):
    access: Optional[List[Union[str, Access]]] = None
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: Optional[str] = None
    flags: Optional[List[AccessTokenFlags]] = None


class SubjectIdentifierFormat(str, Enum):
    ACCOUNT = 'account'
    ALIASES = 'aliases'
    DID = 'did'
    EMAIL = 'email'
    ISS_SUB = 'iss_sub'
    OPAQUE = 'opaque'
    PHONE_NUMBER = 'phone_number'


class SubjectAssertionFormat(str, Enum):
    ID_TOKEN = 'id_token'
    SAML2 = 'saml2'


class SubjectRequest(GnapBaseModel):
    sub_id_formats: Optional[List[SubjectIdentifierFormat]] = None
    assertion_formats: Optional[List[SubjectAssertionFormat]] = None


class Display(GnapBaseModel):
    name: Optional[str] = None
    uri: Optional[str] = None
    logo_uri: Optional[str] = None


class Client(GnapBaseModel):
    key: Union[str, Key]
    class_id: Optional[str] = None
    display: Optional[Display] = None


class SubjectIdentifier(GnapBaseModel):
    # sub_ids should contain objects as {"format": "opaque", "id": "J2G8G8O4AZ"} or
    # {"format": "email", "email": "user@example.com"}
    # see ietf-secevent-subject-identifiers
    format: SubjectIdentifierFormat

    class Config:
        extra = Extra.allow


class SubjectAssertion(GnapBaseModel):
    format: SubjectAssertionFormat
    value: str


class User(GnapBaseModel):
    sub_ids: Optional[List[SubjectIdentifier]] = None
    # An object containing assertions as values keyed on the assertion type.
    # Possible keys include "id_token" for an [OIDC] ID Token and "saml2" for a SAML 2 assertion.
    assertions: Optional[List[SubjectAssertion]] = None


class StartInteractionMethod(str, Enum):
    REDIRECT = 'redirect'
    APP = 'app'
    USER_CODE = 'user_code'  # for use with a stable URI
    USER_CODE_URI = 'user_code_uri'  # for use with a dynamic URI


class FinishInteractionMethod(str, Enum):
    REDIRECT = 'redirect'
    PUSH = 'push'


class HashMethod(str, Enum):
    SHA2 = 'sha2'
    SHA3 = 'sha3'


class FinishInteraction(GnapBaseModel):
    method: FinishInteractionMethod
    uri: AnyUrl
    nonce: str
    hash_method: HashMethod = Field(default=HashMethod.SHA3)


class Hints(GnapBaseModel):
    ui_locales: Optional[List[str]] = None


class InteractionRequest(GnapBaseModel):
    start: List[StartInteractionMethod]
    finish: Optional[FinishInteraction] = None
    hints: Optional[Hints] = None


class GrantRequest(GnapBaseModel):
    access_token: Union[AccessTokenRequest, List[AccessTokenRequest]]
    subject: Optional[SubjectRequest] = None
    client: Union[str, Client]
    user: Optional[Union[str, User]] = None
    interact: Optional[InteractionRequest] = None


class ContinueAccessToken(GnapBaseModel):
    bound: bool = True
    value: str


class Continue(GnapBaseModel):
    uri: AnyUrl
    wait: Optional[int]
    access_token: ContinueAccessToken


class UserCode(GnapBaseModel):
    code: str


class UserCodeURI(GnapBaseModel):
    code: str
    uri: AnyUrl


class InteractionResponse(GnapBaseModel):
    redirect: Optional[AnyUrl] = None
    app: Optional[AnyUrl] = None
    user_code: Optional[UserCode] = None
    user_code_uri: Optional[UserCodeURI] = None
    finish: Optional[str] = None


class AccessTokenResponse(GnapBaseModel):
    value: str
    label: Optional[str] = None
    manage: Optional[AnyUrl] = None
    access: Optional[List[Union[str, Access]]] = None
    expires_in: Optional[int] = Field(default=None, description='seconds until expiry')
    key: Optional[Union[str, Key]] = None
    flags: Optional[List[AccessTokenFlags]] = None


class SubjectResponse(GnapBaseModel):
    sub_ids: Optional[List[SubjectIdentifier]] = None
    assertions: Optional[List[SubjectAssertion]] = None
    updated_at: Optional[datetime] = Field(default=None, description='ISO8610 date string')


class ErrorCode(str, Enum):
    INVALID_REQUEST = 'invalid_request'
    INVALID_CLIENT = 'invalid_client'
    USER_DENIED = 'user_denied'
    TOO_FAST = 'too_fast'
    UNKNOWN_REQUEST = 'unknown_request'
    REQUEST_DENIED = 'request_denied'


# TODO: Change FastApi HTTPException responses to ErrorResponse
class ErrorResponse(BaseModel):
    error: ErrorCode
    error_description: Optional[str] = None


class ContinueRequest(GnapBaseModel):
    interact_ref: Optional[str] = None


class GrantResponse(GnapBaseModel):
    continue_: Optional[Continue] = Field(default=None, alias='continue')
    access_token: Optional[AccessTokenResponse] = None
    interact: Optional[InteractionResponse] = None
    subject: Optional[SubjectResponse] = None
    instance_id: Optional[str] = None
    user_handle: Optional[str] = None


class GNAPJOSEHeader(JOSEHeader):
    kid: str
    alg: SupportedAlgorithms
    typ: SupportedJWSType
    htm: SupportedHTTPMethods
    # The HTTP URI used for this request, including all path and query components.
    uri: str
    # A timestamp of when the signature was created
    created: datetime
    # When a request is bound to an access token, the access token hash value. The value MUST be the result of
    # Base64url encoding (with no padding) the SHA-256 digest of the ASCII encoding of the associated access
    # token's value.  REQUIRED if the request protects an access token.
    ath: Optional[str] = None
