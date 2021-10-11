# -*- coding: utf-8 -*-
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import AnyUrl, BaseModel, Field

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


class Proof(str, Enum):
    DPOP = 'dpop'
    HTTPSIGN = 'httpsign'
    JWSD = 'jwsd'
    JWS = 'jws'
    MTLS = 'mtls'
    OAUTHPOP = 'oauthpop'
    TEST = 'test'


class Key(BaseModel):
    proof: Proof
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]] = None
    cert: Optional[str] = None
    cert_S256: Optional[str] = Field(default=None, alias='cert#S256')

    class Config:
        allow_population_by_field_name = True


class Access(BaseModel):
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


class AccessTokenRequest(BaseModel):
    access: Optional[List[Union[str, Access]]] = None
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: Optional[str] = None
    flags: Optional[List[AccessTokenFlags]] = None


# TODO: sub_ids should correspond to User sub_ids and assertion values
class Subject(BaseModel):
    sub_ids: Optional[List[str]] = None
    assertions: Optional[List[str]] = None


class Display(BaseModel):
    name: Optional[str] = None
    uri: Optional[str] = None
    logo_uri: Optional[str] = None


class Client(BaseModel):
    key: Union[str, Key]
    class_id: Optional[str] = None
    display: Optional[Display] = None


# TODO: Check https://datatracker.ietf.org/doc/html/draft-ietf-secevent-subject-identifiers-06 for
#   implementation details when needed
class User(BaseModel):
    sub_ids: Optional[List[Dict[str, str]]] = None
    assertions: Optional[Dict[str, str]] = None


class StartInteraction(str, Enum):
    REDIRECT = 'redirect'
    APP = 'app'
    USER_CODE = 'user_code'


class FinishInteractionMethod(str, Enum):
    REDIRECT = 'redirect'
    PUSH = 'push'


class HashMethod(str, Enum):
    SHA2 = 'sha2'
    SHA3 = 'sha3'


class FinishInteraction(BaseModel):
    method: FinishInteractionMethod
    uri: AnyUrl
    nonce: str
    hash_method: Optional[HashMethod] = None


class Hints(BaseModel):
    ui_locales: Optional[List[str]] = None


class InteractionRequest(BaseModel):
    start: List[StartInteraction]
    finish: Optional[FinishInteraction] = None
    hints: Optional[Hints] = None


class GrantRequest(BaseModel):
    access_token: Union[AccessTokenRequest, List[AccessTokenRequest]]
    subject: Optional[Subject] = None
    client: Union[str, Client]
    user: Optional[Union[str, User]] = None
    interact: Optional[InteractionRequest] = None


class ContinueAccessToken(BaseModel):
    bound: bool
    value: str


class Continue(BaseModel):
    uri: AnyUrl
    wait: Optional[int]
    access_token: ContinueAccessToken


class UserCode(BaseModel):
    code: str
    url: Optional[AnyUrl] = None


class InteractionResponse(BaseModel):
    redirect: Optional[AnyUrl] = None
    app: Optional[AnyUrl] = None
    user_code: Optional[UserCode] = None
    finish: Optional[str] = None


class AccessTokenResponse(BaseModel):
    value: str
    label: Optional[str] = None
    manage: Optional[AnyUrl] = None
    access: Optional[List[Union[str, Access]]] = None
    expires_in: Optional[int] = Field(default=None, description='seconds until expiry')
    key: Optional[Union[str, Key]] = None
    flags: Optional[List[AccessTokenFlags]] = None


class SubjectResponse(Subject):
    updated_at: Optional[str] = Field(default=None, description='ISO8610 date string')


class Error(str, Enum):
    USER_DENIED = 'user_denied'
    TOO_FAST = 'too_fast'
    UNKNOWN_REQUEST = 'unknown_request'


class GrantResponse(BaseModel):
    continue_: Optional[Continue] = Field(default=None, alias='continue')
    access_token: Optional[AccessTokenResponse] = None
    interact: Optional[InteractionResponse] = None
    subject: Optional[SubjectResponse] = None
    instance_id: Optional[str] = None
    user_handle: Optional[str] = None
    error: Optional[Error] = None


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
    ath: Optional[str]
