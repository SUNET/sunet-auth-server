# -*- coding: utf-8 -*-

import logging
from base64 import b64encode

from cryptography.hazmat.primitives.hashes import SHA256

from auth_server.models.gnap import Key
from auth_server.utils import load_cert_from_str

__author__ = "lundberg"


logger = logging.getLogger(__name__)


async def check_mtls_proof(gnap_key: Key, cert: str) -> bool:
    try:
        tls_cert = load_cert_from_str(cert)
    except ValueError:
        logger.error(f"could not load client cert: {cert}")
        return False

    tls_fingerprint = b64encode(tls_cert.fingerprint(algorithm=SHA256())).decode("utf-8")
    logger.debug(f"tls cert fingerprint: {str(tls_fingerprint)}")

    if gnap_key.cert_S256 is not None:
        logger.debug(f"cert#S256: {gnap_key.cert_S256}")
        if tls_fingerprint == gnap_key.cert_S256:
            logger.info(f"TLS cert fingerprint matches grant request cert#S256")
            return True
        logger.info(f"TLS cert fingerprint does NOT match grant request cert#S256")
    elif gnap_key.cert is not None:
        grant_cert = load_cert_from_str(gnap_key.cert)
        grant_cert_fingerprint = b64encode(grant_cert.fingerprint(algorithm=SHA256())).decode("utf-8")
        logger.debug(f"grant cert fingerprint: {grant_cert_fingerprint}")
        if tls_fingerprint == grant_cert_fingerprint:
            logger.info(f"TLS cert fingerprint matches grant request cert fingerprint")
            return True
        logger.info(f"TLS cert fingerprint does NOT match grant request cert fingerprint")

    return False
