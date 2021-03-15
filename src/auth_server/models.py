# -*- coding: utf-8 -*-
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

__author__ = 'lundberg'

from auth_server.utils import utc_now


class Proof(str, Enum):
    MTLS = 'mtls'
    HTTPSIGN = 'httpsign'
    TEST = 'test'


class Key(BaseModel):
    proof: Proof
    # TODO: kid not in spec
    kid: str


class Resources(BaseModel):
    origins: list = Field(default=[])


class AuthRequest(BaseModel):
    # TODO: keys should be key
    keys: Key
    # TODO: resources not in spec, should be access_token
    resources: Resources


class AccessToken(BaseModel):
    type: str
    value: str


class AuthResponse(BaseModel):
    access_token: AccessToken


class RegisteredClaims(BaseModel):
    """
    https://tools.ietf.org/html/rfc7519#section-4.1
    """

    iss: Optional[str]  # Issuer
    sub: Optional[str]  # Subject
    aud: Optional[str]  # Audience
    exp: Optional[timedelta]  # Expiration Time
    nbf: Optional[datetime] = Field(default=utc_now())  # Not Before
    iat: Optional[datetime] = Field(default=utc_now())  # Issued At
    jti: Optional[str]  # JWT ID

    def to_rfc7519(self):
        d = self.dict(exclude_unset=True)
        if self.exp:
            d['exp'] = int((self.iat + self.exp).timestamp())
        if self.nbf:
            d['nbf'] = int(self.nbf.timestamp())
        if self.iat:
            d['iat'] = int(self.iat.timestamp())
        return d


class Claims(RegisteredClaims):
    origins: List[str]
