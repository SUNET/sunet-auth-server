# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field

from auth_server.utils import utc_now

__author__ = 'lundberg'


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


class SupportedAlgorithms(str, Enum):
    RS256 = 'RS256'
    ES256 = 'ES256'
    ES384 = 'ES384'


class SupportedHTTPMethods(str, Enum):
    POST = 'POST'


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
    origins: Optional[List[str]] = None  # What should we use this for?


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


# Workaround for mypy not liking Union[ECJWK, RSAJWK, SymmetricJWK] as response_model. It should work.
# https://github.com/tiangolo/fastapi/issues/2279
class JWKTypes(BaseModel):
    __root__: Union[ECJWK, RSAJWK, SymmetricJWK]


class JWKS(BaseModel):
    keys: List[Union[ECJWK, RSAJWK, SymmetricJWK]]


class JWSHeaders(BaseModel):
    """
    The header of the JWS MUST contain the "kid" field of the key bound
    to this client instance for this request.  The JWS header MUST
    contain an "alg" field appropriate for the key identified by "kid"
    and MUST NOT be "none".

    To protect the request, the JWS header MUST contain the following
    additional fields.
    """

    alg: SupportedAlgorithms
    kid: str
    htm: SupportedHTTPMethods
    htu: str  # The HTTP URI used for this request, including all path and query components.
    ts: int
    # at_hash value is the base64url encoding of the left-most half of the hash of the octets of the ASCII
    # representation of the "access_token" value ex. if the "alg" is "RS256", hash the "access_token"
    # value with SHA-256, then take the left-most 128 bits and base64url encode them.
    at_hash: str
