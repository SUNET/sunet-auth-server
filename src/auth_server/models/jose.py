# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field

from auth_server.utils import utc_now

__author__ = 'lundberg'


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


class KeyType(str, Enum):
    EC = 'EC'
    RSA = 'RSA'
    OCT = 'oct'


class KeyUse(str, Enum):
    SIGN = 'sig'
    ENCRYPT = 'enc'


class KeyOptions(str, Enum):
    SIGN = 'sign'
    VERIFY = 'verify'
    ENCRYPT = 'encrypt'
    DECRYPT = 'decrypt'
    WRAP_KEY = 'wrapKey'
    UNWRAP_KEY = 'unwrapKey'
    DERIVE_KEY = 'deriveKey'
    DERIVE_BITS = 'deriveBits'


class JWK(BaseModel):
    kty: KeyType
    use: Optional[KeyUse]
    key_opts: Optional[List[KeyOptions]]
    alg: Optional[str]
    kid: Optional[str]
    x5u: Optional[str]
    x5c: Optional[str]
    x5t: Optional[str]
    x5tS256: Optional[str] = Field(alias='x5t#S256')


class ECJWK(JWK):
    crv: Optional[str]
    x: Optional[str]
    y: Optional[str]
    d: Optional[str]
    n: Optional[str]
    e: Optional[str]


class RSAJWK(JWK):
    d: Optional[str]
    n: Optional[str]
    e: Optional[str]
    p: Optional[str]
    q: Optional[str]
    dp: Optional[str]
    dq: Optional[str]
    qi: Optional[str]
    oth: Optional[str]
    r: Optional[str]
    t: Optional[str]


class SymmetricJWK(JWK):
    k: Optional[str]


class JWKS(BaseModel):
    keys: List[Union[ECJWK, RSAJWK, SymmetricJWK]]
