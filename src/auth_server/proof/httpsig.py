"""
GNAP httpsig key proof (RFC 9635 7.3.1) using HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530).
"""

import hashlib
import hmac
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Self, cast

import http_sf
from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver
from http_message_signatures.algorithms import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PSS_SHA512,
    RSA_V1_5_SHA256,
    HTTPSignatureAlgorithm,
)
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from jwcrypto.jwk import JWK, InvalidJWKValue

from auth_server.config import load_config
from auth_server.context import ContextRequest
from auth_server.db.proof_nonce import get_proof_nonce_store
from auth_server.errors import GNAPErrorException
from auth_server.models.gnap import ErrorCode, Key
from auth_server.models.jose import KeyType, KeyUse
from auth_server.proof.common import get_target_uri

__author__ = "lundberg"

logger = logging.getLogger(__name__)

GNAP_TAG = "gnap"
DEFAULT_CONTENT_DIGEST_ALG = "sha-256"
CONTENT_DIGEST_ALGS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
# JWK parameters that must never be part of a key sent by value
PRIVATE_JWK_PARAMS = ("d", "p", "q", "dp", "dq", "qi", "oth", "r", "t", "k")


@dataclass(frozen=True)
class HttpsigAlgorithm:
    name: str  # RFC 9421 algorithm name
    implementation: type[HTTPSignatureAlgorithm]
    kty: KeyType
    crv: str | None = None


HTTPSIG_ALGORITHMS: dict[str, HttpsigAlgorithm] = {
    alg.name: alg
    for alg in [
        HttpsigAlgorithm("ecdsa-p256-sha256", ECDSA_P256_SHA256, KeyType.EC, "P-256"),
        HttpsigAlgorithm("ecdsa-p384-sha384", ECDSA_P384_SHA384, KeyType.EC, "P-384"),
        HttpsigAlgorithm("rsa-v1_5-sha256", RSA_V1_5_SHA256, KeyType.RSA),
        HttpsigAlgorithm("rsa-pss-sha512", RSA_PSS_SHA512, KeyType.RSA),
        HttpsigAlgorithm("ed25519", ED25519, KeyType.OKP, "Ed25519"),
    ]
}
# JWS algorithm name (JWK "alg") to RFC 9421 algorithm name. No HMAC, the key must be asymmetric.
JWS_ALG_TO_HTTPSIG_ALG = {
    "ES256": "ecdsa-p256-sha256",
    "ES384": "ecdsa-p384-sha384",
    "RS256": "rsa-v1_5-sha256",
    "PS512": "rsa-pss-sha512",
    "EdDSA": "ed25519",
}


def _reject(description: str) -> GNAPErrorException:
    logger.error(f"httpsig: {description}")
    return GNAPErrorException(status_code=400, error_code=ErrorCode.INVALID_CLIENT, description=description)


# a parsed structured field member: value (inner list for signature input) and parameters
SFMember = tuple[object, dict[str, object]]


class _SingleKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self: Self, key_id: str, public_key: PublicKeyTypes) -> None:
        self.key_id = key_id
        self.public_key = public_key

    def resolve_public_key(self: Self, key_id: str) -> PublicKeyTypes | None:
        return self.public_key if key_id == self.key_id else None

    def resolve_private_key(self: Self, key_id: str) -> PublicKeyTypes:
        raise NotImplementedError("the auth server never signs with a client key")


class _Headers:
    """Read only header view with repeated field lines, as needed by http_message_signatures"""

    def __init__(self: Self, fields: list[tuple[str, str]]) -> None:
        self._fields = fields

    def items(self: Self) -> Iterable[tuple[str, str]]:
        return list(self._fields)

    def __iter__(self: Self) -> Iterator[str]:
        return iter(dict.fromkeys(name for name, _ in self._fields))

    def __contains__(self: Self, name: str) -> bool:
        return any(field.lower() == name.lower() for field, _ in self._fields)


class _Message:
    def __init__(self: Self, method: str, url: str, headers: _Headers) -> None:
        self.method = method
        self.url = url
        self.headers = headers


@dataclass(frozen=True)
class _ClientKey:
    fingerprint: str  # identifies the key and the parameters bound to it
    algorithm: HttpsigAlgorithm
    public_key: PublicKeyTypes
    kid: str
    content_digest_alg: str


def _load_client_key(gnap_key: Key) -> _ClientKey:
    """Validate the key and proof parameters and derive the algorithm from them, never from the message."""
    jwk = gnap_key.jwk
    if jwk is None:
        raise _reject("httpsig requires the key to be a JWK")
    if jwk.kty not in (KeyType.EC, KeyType.RSA, KeyType.OKP):
        raise _reject(f"key type {jwk.kty} is not supported for httpsig")
    if any(getattr(jwk, param, None) is not None for param in PRIVATE_JWK_PARAMS):
        raise _reject("the key must be a public key, private key parameters found")
    if jwk.use is not None and jwk.use is not KeyUse.SIGN:
        raise _reject("the key is not meant for signatures")
    if not jwk.kid:
        raise _reject("the key needs a kid, it is used as keyid in the signature")

    proof = gnap_key.proof
    if proof.alg is None:
        # string form, the algorithm must come from the key material
        if jwk.alg is None:
            raise _reject("the key needs an alg when the httpsig proof is given as a string")
        httpsig_alg = JWS_ALG_TO_HTTPSIG_ALG.get(jwk.alg)
        if httpsig_alg is None:
            raise _reject(f"key alg {jwk.alg} is not supported for httpsig")
    else:
        httpsig_alg = proof.alg
        if httpsig_alg not in HTTPSIG_ALGORITHMS:
            raise _reject(f"proof alg {httpsig_alg} is not supported")
        if jwk.alg is not None and JWS_ALG_TO_HTTPSIG_ALG.get(jwk.alg) != httpsig_alg:
            raise _reject("proof alg does not match key alg")
    algorithm = HTTPSIG_ALGORITHMS[httpsig_alg]

    if jwk.kty is not algorithm.kty or (algorithm.crv is not None and getattr(jwk, "crv", None) != algorithm.crv):
        raise _reject(f"the key can not be used with {algorithm.name}")

    content_digest_alg = (proof.content_digest_alg or DEFAULT_CONTENT_DIGEST_ALG).lower()
    if content_digest_alg not in CONTENT_DIGEST_ALGS:
        raise _reject(f"content-digest-alg {content_digest_alg} is not supported")

    key_params = {name: getattr(jwk, name, None) for name in ("kty", "crv", "x", "y", "n", "e")}
    try:
        public_key = JWK(**{name: str(value) for name, value in key_params.items() if value is not None}).get_op_key(
            "verify"
        )
    except (InvalidJWKValue, ValueError, TypeError) as e:
        raise _reject(f"invalid key: {e}")
    fingerprint = hashlib.sha256(
        "|".join([algorithm.name, content_digest_alg, jwk.kid, *(str(v) for v in key_params.values())]).encode()
    ).hexdigest()
    return _ClientKey(
        fingerprint=fingerprint,
        algorithm=algorithm,
        public_key=public_key,
        kid=jwk.kid,
        content_digest_alg=content_digest_alg,
    )


def _parse_dictionary_header(request: ContextRequest, name: str) -> dict[str, SFMember]:
    def reject_duplicate(key: str, context: str) -> None:
        if context == "dictionary":
            raise ValueError(f"duplicate member {key}")

    try:
        return cast(
            dict[str, SFMember],
            http_sf.parse(
                ", ".join(request.headers.getlist(name)).encode("ascii"),
                tltype="dictionary",
                on_duplicate_key=reject_duplicate,
            ),
        )
    except (ValueError, TypeError, UnicodeError) as e:
        raise _reject(f"malformed {name} header: {e}")


def _check_content_digest(request: ContextRequest, body: bytes, content_digest_alg: str) -> None:
    """Check the Content-Digest header against the raw body using the digest algorithm bound to the key."""
    if "content-digest" not in request.headers:
        if body:
            raise _reject("content-digest header is required when there is a request body")
        return
    digests = _parse_dictionary_header(request, "content-digest")
    digest = digests.get(content_digest_alg)
    if digest is None or not isinstance(digest[0], bytes):
        raise _reject(f"content-digest has no {content_digest_alg} digest")
    expected = CONTENT_DIGEST_ALGS[content_digest_alg](body).digest()
    if not hmac.compare_digest(digest[0], expected):
        raise _reject("content-digest does not match the request body")


@dataclass(frozen=True)
class _RequestData:
    """What is the same for every signature in the request"""

    request: ContextRequest
    body: bytes
    url: str
    fields: list[tuple[str, str]]  # all header fields except the signature ones
    access_token: str | None


async def _verify_signature(
    label: str, signature_input: SFMember, signature: SFMember, data: _RequestData, client_key: _ClientKey
) -> str | None:
    """Verify one signature. Returns the nonce of the signature, if any."""
    config = load_config()

    if not isinstance(signature_input[0], list):
        raise _reject(f"signature input {label} is not a list of components")
    params = signature_input[1]

    if params.get("tag") != GNAP_TAG:
        raise _reject(f'signature tag must be "{GNAP_TAG}"')
    if "alg" in params:
        raise _reject("the alg signature parameter must not be used, the algorithm is bound to the key")
    if type(params.get("created")) is not int:
        raise _reject("the created signature parameter is required")
    if params.get("keyid") != client_key.kid:
        raise _reject("keyid does not match the kid of the key bound to the grant")
    nonce = params.get("nonce")
    if nonce is None and config.proof_httpsig_nonce_required:
        raise _reject("a signed nonce is required")
    if nonce is not None and (not isinstance(nonce, str) or not nonce):
        raise _reject("invalid nonce")

    required_components = ["@method", "@target-uri"]
    if data.body:
        required_components.append("content-digest")
        if config.proof_httpsig_require_content_type:
            required_components.append("content-type")
    if data.access_token is not None:
        required_components.append("authorization")

    # only hand the signature being verified to the library, other signatures can not affect the result
    fields = [
        *data.fields,
        ("Signature-Input", http_sf.ser(cast(dict, {label: signature_input}))),
        ("Signature", http_sf.ser(cast(dict, {label: signature}))),
    ]
    message = _Message(method=data.request.method, url=data.url, headers=_Headers(fields))

    verifier = HTTPMessageVerifier(
        signature_algorithm=client_key.algorithm.implementation,
        key_resolver=_SingleKeyResolver(key_id=client_key.kid, public_key=client_key.public_key),
    )
    verifier.max_clock_skew = config.proof_httpsig_clock_skew
    try:
        verifier.verify(
            message,
            max_age=config.proof_httpsig_max_age,
            expect_tag=GNAP_TAG,
            expect_label=label,
            require_components=required_components,
        )
    except (HTTPMessageSignaturesException, CryptographyInvalidSignature) as e:
        # the cryptography exception has no message
        raise _reject(f"signature {label} could not be verified: {e}" if str(e) else "signature is not valid")
    return nonce if isinstance(nonce, str) else None


async def check_httpsig_proof(request: ContextRequest, gnap_key: Key, access_token: str | None = None) -> bool:
    # The caller (BaseAuthFlow.check_proof) moves on to the next flow when there are no signature headers
    config = load_config()
    client_key = _load_client_key(gnap_key)

    # A flow can fall through to the next flow, that will check the proof again. A nonce can only be used once
    # so the result of a verification is kept for the rest of the request.
    verified_key = f"{client_key.fingerprint}|{access_token or ''}"
    if verified_key in request.context.httpsig_verified:
        logger.debug("httpsig proof already verified for this request")
        return True

    body = await request.body()
    _check_content_digest(request=request, body=body, content_digest_alg=client_key.content_digest_alg)

    signature_inputs = _parse_dictionary_header(request, "signature-input")
    signatures = _parse_dictionary_header(request, "signature")
    if not signature_inputs:
        raise _reject("no signatures found")

    data = _RequestData(
        request=request,
        body=body,
        url=get_target_uri(request),
        fields=[
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in request.headers.raw
            if name.lower() not in (b"signature", b"signature-input")
        ],
        access_token=access_token,
    )

    # the request is accepted if any one signature satisfies every check
    error: GNAPErrorException | None = None
    for label, signature_input in signature_inputs.items():
        try:
            signature = signatures.get(label)
            if signature is None or not isinstance(signature[0], bytes):
                raise _reject(f"no signature found for signature input {label}")
            nonce = await _verify_signature(
                label=label, signature_input=signature_input, signature=signature, data=data, client_key=client_key
            )
            # The nonce is only stored for a verified signature so that unauthenticated requests can not use up
            # nonces. The ttl has a margin over the longest time a signature can be accepted.
            if nonce is not None:
                ttl = config.proof_httpsig_max_age + 3 * config.proof_httpsig_clock_skew + timedelta(seconds=60)
                nonce_store = await get_proof_nonce_store(ttl=ttl)
                # scoped to the validated key material, the kid is client chosen and not unique across clients
                if not await nonce_store.check_and_store(key_fingerprint=client_key.fingerprint, nonce=nonce):
                    raise _reject("nonce has already been used")
        except GNAPErrorException as e:
            error = e
            continue
        logger.info(f"httpsig signature {label} verified")
        request.context.httpsig_verified.add(verified_key)
        return True
    assert error is not None  # please mypy, signature_inputs is not empty
    raise error
