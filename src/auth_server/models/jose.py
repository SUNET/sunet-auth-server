# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Union

from pydantic import AnyUrl, BaseModel, Field

from auth_server.time_utils import utc_now

__author__ = "lundberg"


class KeyType(str, Enum):
    EC = "EC"
    RSA = "RSA"
    OCT = "oct"


class KeyUse(str, Enum):
    SIGN = "sig"
    ENCRYPT = "enc"


class KeyOptions(str, Enum):
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    WRAP_KEY = "wrapKey"
    UNWRAP_KEY = "unwrapKey"
    DERIVE_KEY = "deriveKey"
    DERIVE_BITS = "deriveBits"


class SupportedAlgorithms(str, Enum):
    RS256 = "RS256"
    ES256 = "ES256"
    ES384 = "ES384"


class SupportedHTTPMethods(str, Enum):
    POST = "POST"


class RegisteredClaims(BaseModel):
    """
    https://tools.ietf.org/html/rfc7519#section-4.1
    """

    iss: Optional[str] = None  # Issuer
    sub: Optional[str] = None  # Subject
    aud: Optional[str] = None  # Audience
    exp: Optional[timedelta] = None  # Expiration Time
    nbf: Optional[datetime] = Field(default_factory=utc_now)  # Not Before
    iat: Optional[datetime] = Field(default_factory=utc_now)  # Issued At
    jti: Optional[str] = None  # JWT ID

    def to_rfc7519(self):
        d = self.dict(exclude_none=True)
        if self.exp:
            d["exp"] = int((self.iat + self.exp).timestamp())
        if self.nbf:
            d["nbf"] = int(self.nbf.timestamp())
        if self.iat:
            d["iat"] = int(self.iat.timestamp())
        return d


class JWK(BaseModel):
    kty: KeyType
    use: Optional[KeyUse] = None
    key_opts: Optional[List[KeyOptions]] = None
    alg: Optional[str] = None
    kid: Optional[str] = None
    x5u: Optional[str] = None
    x5c: Optional[str] = None
    x5t: Optional[str] = None
    x5tS256: Optional[str] = Field(default=None, alias="x5t#S256")


class ECJWK(JWK):
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    d: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None


class RSAJWK(JWK):
    d: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    dp: Optional[str] = None
    dq: Optional[str] = None
    qi: Optional[str] = None
    oth: Optional[str] = None
    r: Optional[str] = None
    t: Optional[str] = None


class SymmetricJWK(JWK):
    k: Optional[str] = None


class JWKS(BaseModel):
    keys: List[Union[ECJWK, RSAJWK, SymmetricJWK]]


class SupportedJWSType(str, Enum):
    JWS = "gnap-binding+jws"
    JWSD = "gnap-binding+jwsd"


class JOSEHeader(BaseModel):
    kid: Optional[str] = None
    alg: SupportedAlgorithms
    jku: Optional[AnyUrl] = None
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]] = None
    x5u: Optional[str] = None
    x5c: Optional[str] = None
    x5t: Optional[str] = None
    x5tS256: Optional[str] = Field(default=None, alias="x5t#S256")
    typ: Optional[str] = None
    cty: Optional[str] = None
    crit: Optional[List] = None
