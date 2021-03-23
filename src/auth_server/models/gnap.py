# -*- coding: utf-8 -*-
from enum import Enum
from typing import Optional, List, Union, Dict

from pydantic import BaseModel, Field, HttpUrl, AnyUrl

from auth_server.models.jose import JWK

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
    jwk: Optional[JWK] = None
    cert: Optional[str] = None
    cert_S256: Optional[str] = Field(default=None, alias='cert#S256')


class Resources(BaseModel):
    origins: list = Field(default=[])


class AccessType(str, Enum):
    """
    Can really be anything, let's start with access
    """
    ACCESS = 'access'


class AccessAction(str, Enum):
    """
    Can really be anything, let's start with read/write
    """
    ALL = 'all'
    READ = 'read'
    WRITE = 'write'


class Access(BaseModel):
    type: Optional[AccessType] = Field(default=AccessType.ACCESS)
    actions: Optional[List[AccessAction]] = Field(default=[AccessAction.ALL])
    locations: Optional[List[AnyUrl]] = Field(default=[])
    datatypes: Optional[List[str]]


class AccessTokenRequestFlags(str, Enum):
    BEARER = 'bearer'
    SPLIT = 'split'


class AccessTokenRequest(BaseModel):
    access: Optional[List[Access]] = []
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: Optional[str] = None
    flags: Optional[List[AccessTokenRequestFlags]] = []


# TODO: sub_ids should correspond to User sub_ids and assertion values
class Subject(BaseModel):
    sub_ids: Optional[List[str]] = []
    assertions: Optional[List[str]] = []


class Display(BaseModel):
    name: Optional[str] = None
    uri: Optional[str] = None
    logo_uri: Optional[str] = None


class Client(BaseModel):
    key: Union[str, Key]
    class_id: Optional[str] = None
    display: Optional[Display] = None


class ClientInstance(BaseModel):
    instance_id: str


# TODO: Check https://datatracker.ietf.org/doc/html/draft-ietf-secevent-subject-identifiers-06 for
#   implementation details when needed
class User(BaseModel):
    sub_ids: Optional[List[Dict[str, str]]] = []
    assertions: Optional[Dict[str, str]] = {}


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
    ui_locales: Optional[List[str]]


class InteractionRequest(BaseModel):
    start: List[StartInteraction]
    finish: Optional[FinishInteraction] = None
    hints: Optional[Hints] = None


class GrantRequest(BaseModel):
    access_token: Union[AccessTokenRequest, List[AccessTokenRequest]]
    subject: Optional[Subject] = None
    client: Union[str, ClientInstance, Client]
    user: Optional[Union[str, User]] = None
    interact: Optional[InteractionRequest] = None
    capabilities: Optional[List[str]] = None
    existing_grant: Optional[str]


class ContinueAccessToken(BaseModel):
    bound: True
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


class ResponseAccessToken(BaseModel):
    value: str
    bound: Optional[bool] = None
    label: Optional[str] = None
    manage: Optional[AnyUrl] = None
    access: Optional[List[str, Access]] = None
    expires_in: Optional[int] = Field(default=None, description='seconds until expiry')
    key: Optional[Union[str, Key]] = None
    durable: Optional[bool] = None
    split: Optional[bool] = None


class SubjectResponse(Subject):
    updated_at: Optional[str] = Field(default=None, description='ISO8610 date string')


class Error(str, Enum):
    USER_DENIED = 'user_denied'
    TOO_FAST = 'too_fast'
    UNKNOWN_REQUEST = 'unknown_request'


class GrantResponse(BaseModel):
    continue_: Continue = Field(alias='continue')
    access_token: ResponseAccessToken
    interact: Optional[InteractionResponse] = None
    subject: Optional[SubjectResponse] = None
    instance_id: Optional[str] = None
    user_handle: Optional[str] = None
    error: Optional[Error] = None



