# -*- coding: utf-8 -*-
__author__ = "lundberg"

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate, load_der_x509_certificate, load_pem_x509_certificate
from loguru import logger
from pki_tools import Certificate as PKIToolCertificate
from pki_tools import Chain
from pki_tools import Error as PKIToolsError
from pki_tools import is_revoked

from auth_server.config import ConfigurationError, load_config


def cert_within_validity_period(cert: Certificate) -> bool:
    """
    check if certificate is within the validity period
    """
    cert_fingerprint = cert.fingerprint(SHA256())
    now = datetime.utcnow()
    if now < cert.not_valid_before:
        logger.error(f"Certificate {cert_fingerprint!r} not valid before {cert.not_valid_before}")
        return False
    if now > cert.not_valid_after:
        logger.error(f"Certificate {cert_fingerprint!r} not valid after {cert.not_valid_after}")
        return False
    return True


def cert_signed_by_ca(cert: Certificate) -> Optional[Certificate]:
    """
    check if the cert is signed by any on our loaded CA certs
    """
    cert_fingerprint = cert.fingerprint(SHA256())
    for ca_cert in load_ca_certs():
        try:
            cert.verify_directly_issued_by(ca_cert)
            logger.debug(f"Certificate {cert_fingerprint!r} signed by CA cert {ca_cert.fingerprint(SHA256())!r}")
            return ca_cert
        except (ValueError, TypeError, InvalidSignature):
            continue

    logger.error(f"Certificate {cert_fingerprint!r} did NOT match any loaded CA cert")
    return None


async def is_cert_revoked(cert: Certificate, ca_cert: Certificate) -> bool:
    """
    check if cert is revoked
    """
    try:
        return is_revoked(
            cert=PKIToolCertificate.from_cryptography(cert=cert), chain=Chain.from_cryptography([ca_cert])
        )
    except PKIToolsError as e:
        logger.error(f"Certificate {cert.fingerprint(SHA256())!r} failed revoke check: {e}")
    return True


@lru_cache()
def load_ca_certs() -> list[Certificate]:
    config = load_config()
    if config.ca_certs_path is None:
        raise ConfigurationError("no CA certs path specified in config")
    certs = []
    path = Path(config.ca_certs_path)
    for crt in path.glob("**/*.crt"):
        try:
            with open(crt, "rb") as f:
                content = f.read()
                try:
                    certs.append(load_pem_x509_certificate(content))
                except ValueError:
                    certs.append(load_der_x509_certificate(content))
        except (IOError, ValueError) as e:
            logger.error(f"Failed to load CA cert {crt}: {e}")
    return certs


def load_cert_from_str(cert: str) -> Certificate:
    if not cert.startswith("-----BEGIN CERTIFICATE-----"):
        cert = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
    return load_pem_x509_certificate(cert.encode())


def serialize_certificate(cert: Certificate) -> str:
    return cert.public_bytes(encoding=Encoding.PEM).decode("utf-8")
