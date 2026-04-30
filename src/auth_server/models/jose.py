from datetime import datetime, timedelta
from enum import StrEnum
from typing import Self

from pydantic import AnyUrl, BaseModel, Field

from auth_server.time_utils import utc_now

__author__ = "lundberg"


class KeyType(StrEnum):
    EC = "EC"
    RSA = "RSA"
    OCT = "oct"


class KeyUse(StrEnum):
    SIGN = "sig"
    ENCRYPT = "enc"


class KeyOptions(StrEnum):
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    WRAP_KEY = "wrapKey"
    UNWRAP_KEY = "unwrapKey"
    DERIVE_KEY = "deriveKey"
    DERIVE_BITS = "deriveBits"


class SupportedAlgorithms(StrEnum):
    RS256 = "RS256"
    ES256 = "ES256"
    ES384 = "ES384"


class SupportedHTTPMethods(StrEnum):
    POST = "POST"


class RegisteredClaims(BaseModel):
    """
    https://tools.ietf.org/html/rfc7519#section-4.1
    """

    iss: str | None = None  # Issuer
    sub: str | None = None  # Subject
    aud: str | None = None  # Audience
    exp: timedelta | None = None  # Expiration Time
    nbf: datetime | None = Field(default_factory=utc_now)  # Not Before
    iat: datetime | None = Field(default_factory=utc_now)  # Issued At
    jti: str | None = None  # JWT ID

    def to_rfc7519(self: Self) -> dict:
        d = self.model_dump(exclude_none=True)
        if self.iat and self.exp:
            d["exp"] = int((self.iat + self.exp).timestamp())
        if self.nbf:
            d["nbf"] = int(self.nbf.timestamp())
        if self.iat:
            d["iat"] = int(self.iat.timestamp())
        return d


class JWK(BaseModel):
    kty: KeyType
    use: KeyUse | None = None
    key_opts: list[KeyOptions] | None = None
    alg: str | None = None
    kid: str | None = None
    x5u: str | None = None
    x5c: str | None = None
    x5t: str | None = None
    x5tS256: str | None = Field(default=None, alias="x5t#S256")


class ECJWK(JWK):
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    d: str | None = None
    n: str | None = None
    e: str | None = None


class RSAJWK(JWK):
    d: str | None = None
    n: str | None = None
    e: str | None = None
    p: str | None = None
    q: str | None = None
    dp: str | None = None
    dq: str | None = None
    qi: str | None = None
    oth: str | None = None
    r: str | None = None
    t: str | None = None


class SymmetricJWK(JWK):
    k: str | None = None


class JWKS(BaseModel):
    keys: list[ECJWK | RSAJWK | SymmetricJWK]


class SupportedJWSTypeLegacy(StrEnum):
    JWS = "gnap-binding+jws"
    JWSD = "gnap-binding+jwsd"


class SupportedJWSType(StrEnum):
    JWS = "gnap-binding-jws"
    JWSD = "gnap-binding-jwsd"


class JOSEHeader(BaseModel):
    kid: str | None = None
    alg: SupportedAlgorithms
    jku: AnyUrl | None = None
    jwk: ECJWK | RSAJWK | SymmetricJWK | None = None
    x5u: str | None = None
    x5c: str | None = None
    x5t: str | None = None
    x5tS256: str | None = Field(default=None, alias="x5t#S256")
    typ: str | None = None
    cty: str | None = None
    crit: list | None = None
