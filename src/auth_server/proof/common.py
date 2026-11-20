import logging
from urllib.parse import unquote

from starlette.requests import Request

from auth_server.config import ClientKey, ConfigurationError, load_config
from auth_server.models.gnap import Key
from auth_server.models.jose import ECJWK, OKPJWK, RSAJWK, KeyType, SymmetricJWK

__author__ = "lundberg"

logger = logging.getLogger(__name__)


async def load_config_key(client_key: ClientKey) -> Key:
    logger.info("Trying to load client key from config")
    logger.debug(f"client_key: {client_key}")

    # JWK
    if client_key.jwk:
        logger.info("Loading JWK from config")
        logger.debug(f"client_key.jwk: {client_key.jwk}")
        if client_key.jwk.kty is KeyType.EC:
            return Key(proof=client_key.proof, jwk=ECJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.RSA:
            return Key(proof=client_key.proof, jwk=RSAJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.OKP:
            return Key(proof=client_key.proof, jwk=OKPJWK(**client_key.jwk.dict(exclude_unset=True)))
        elif client_key.jwk.kty is KeyType.OCT:
            return Key(proof=client_key.proof, jwk=SymmetricJWK(**client_key.jwk.dict(exclude_unset=True)))
        else:
            logger.error(f"JWK type {client_key.jwk.kty} not implemented")
            raise NotImplementedError(f"JWK type {client_key.jwk.kty} not implemented")
    # cert
    elif client_key.cert:
        logger.info("Loading cert from config")
        logger.debug(f"client_key.cert: {client_key.cert}")
        return Key(proof=client_key.proof, cert=client_key.cert)
    # cert#S256
    elif client_key.cert_S256:
        logger.info("Loading cert_S256 from config")
        logger.debug(f"client_key.cert_S256: {client_key.cert_S256}")
        return Key(proof=client_key.proof, cert_S256=client_key.cert_S256)

    raise ConfigurationError("malformed client key in config")


async def lookup_client_key_from_config(key_reference: str) -> Key | None:
    config = load_config()
    client_key = None

    # Look for a key in config
    if key_reference in config.client_keys:
        client_key = await load_config_key(config.client_keys[key_reference])

    return client_key


def _get_raw_path(request: Request) -> str:
    """
    The path as the client sent it, still percent-encoded. A request to /%74ransaction is routed to /transaction but
    that is not what the client signed.

    uvicorn (checked with 0.49) and the Starlette TestClient (checked with 1.3) provide scope["raw_path"] next to a
    decoded scope["path"]. uvicorn prefixes both with root_path, the TestClient prefixes neither, so raw_path is
    used as is. A server that does something else with raw_path, or does not provide it, gets the decoded path.
    """
    path: str = request.scope["path"]
    raw_path = request.scope.get("raw_path")
    if not raw_path:
        return path
    try:
        raw = raw_path.split(b"?", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return path
    if unquote(raw) != path:
        # not the same path, e.g. a raw_path without root_path. Better to not trust it.
        return path
    return raw


def get_target_uri(request: Request) -> str:
    """
    The URI a client signs for a request (RFC 9421 @target-uri, GNAP jws/jwsd uri).

    The path and query are the ones the client sent, byte for byte. If proof_external_base_url is set, scheme and
    authority are taken from it and the rest from the request. The scheme and host are never taken from forwarded
    headers, as they would be client controlled.
    """
    config = load_config()
    if config.proof_external_base_url is None:
        url = request.url
        origin = f"{url.scheme}://{url.netloc}"
    else:
        base = config.proof_external_base_url
        authority = base.host or ""
        if base.port is not None and base.port != {"http": 80, "https": 443}.get(base.scheme):
            authority = f"{authority}:{base.port}"
        origin = f"{base.scheme}://{authority}"
    uri = f"{origin}{_get_raw_path(request)}"
    query = request.scope.get("query_string", b"").decode("latin-1")
    if query:
        uri = f"{uri}?{query}"
    return uri
