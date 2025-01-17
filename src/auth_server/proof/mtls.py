import logging

from auth_server.cert_utils import load_pem_from_str, rfc8705_fingerprint
from auth_server.models.gnap import Key

__author__ = "lundberg"

logger = logging.getLogger(__name__)


async def check_mtls_proof(gnap_key: Key, cert: str) -> bool:
    try:
        tls_cert = load_pem_from_str(cert)
    except ValueError:
        logger.error(f"could not load client cert: {cert}")
        return False

    tls_fingerprint = rfc8705_fingerprint(tls_cert)
    logger.debug(f"tls cert fingerprint: {str(tls_fingerprint)}")

    if gnap_key.cert_S256 is not None:
        logger.debug(f"cert#S256: {gnap_key.cert_S256}")
        if tls_fingerprint == gnap_key.cert_S256:
            logger.info("TLS cert fingerprint matches grant request cert#S256")
            return True
        logger.info("TLS cert fingerprint does NOT match grant request cert#S256")
    elif gnap_key.cert is not None:
        grant_cert = load_pem_from_str(gnap_key.cert)
        grant_cert_fingerprint = rfc8705_fingerprint(grant_cert)
        logger.debug(f"grant cert fingerprint: {grant_cert_fingerprint}")
        if tls_fingerprint == grant_cert_fingerprint:
            logger.info("TLS cert fingerprint matches grant request cert fingerprint")
            return True
        logger.info("TLS cert fingerprint does NOT match grant request cert fingerprint")

    logger.info("TLS cert does NOT match grant request cert")
    logger.debug(f"tried gnap_key.cert_S256: {bool(gnap_key.cert_S256)}")
    logger.debug(f"tried gnap_key.cert: {bool(gnap_key.cert)}")
    return False
