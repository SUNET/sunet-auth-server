__author__ = "lundberg"

import logging
from base64 import b64encode
from datetime import datetime
from enum import Enum
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate, ExtensionNotFound, Name, load_der_x509_certificate, load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID
from pki_tools import Certificate as PKIToolCertificate
from pki_tools import Chain, is_revoked
from pki_tools import Error as PKIToolsError

from auth_server.config import ConfigurationError, load_config

logger = logging.getLogger(__name__)

OID_COMMON_NAME = ObjectIdentifier("2.5.4.3")
OID_ORGANIZATION_NAME = ObjectIdentifier("2.5.4.10")
OID_COUNTRY_CODE = ObjectIdentifier("2.5.4.6")
OID_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")
OID_ENHANCED_KEY_USAGE_CLIENT_AUTHENTICATION = ObjectIdentifier("1.3.6.1.5.5.7.3.2")


class SupportedOrgIdCA(str, Enum):
    EFOS = "Swedish Social Insurance Agency"
    EXPITRUST = "Expisoft AB"
    SITHS = "Inera AB"


def cert_within_validity_period(cert: Certificate) -> bool:
    """
    check if certificate is within the validity period
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    now = datetime.utcnow()  # datetimes in cert are not timezone aware
    if now < cert.not_valid_before:
        logger.error(f"Certificate {cert_fingerprint} not valid before {cert.not_valid_before}")
        return False
    if now > cert.not_valid_after:
        logger.error(f"Certificate {cert_fingerprint} not valid after {cert.not_valid_after}")
        return False
    return True


@lru_cache
def cert_signed_by_ca(cert: Certificate) -> str | None:
    """
    check if the cert is signed by any on our loaded CA certs
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    for ca_name, ca_cert in load_ca_certs().items():
        try:
            cert.verify_directly_issued_by(ca_cert)
            logger.debug(f"Certificate {cert_fingerprint} signed by CA cert {ca_name}")
            return ca_name
        except (ValueError, TypeError, InvalidSignature):
            continue

    logger.error(f"Certificate {cert_fingerprint} did NOT match any loaded CA cert")
    return None


@lru_cache
def get_chain(cert: Certificate) -> list[Certificate]:
    chain = list()
    # please mypy
    _cert: Certificate | None = cert
    while ca_name := cert_signed_by_ca(_cert):
        _cert = load_ca_certs().get(ca_name)
        if _cert:
            chain.append(_cert)
        if _cert is None or ca_name == _cert.issuer.rfc4514_string():  # no cert of signed by self
            break
    return chain


async def is_cert_revoked(cert: Certificate) -> bool:
    """
    check if cert is revoked
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    ca_chain = get_chain(cert)
    if not ca_chain:
        raise ConfigurationError(f"No CA cert found for certificate {cert_fingerprint}")
    try:
        return is_revoked(cert=PKIToolCertificate.from_cryptography(cert=cert), chain=Chain.from_cryptography(ca_chain))
    except (PKIToolsError, ValueError) as e:
        logger.error(f"Certificate {cert_fingerprint} failed revoke check: {e}")
    return True


def get_org_id_from_cert(cert: Certificate, ca_name: str) -> str | None:
    ca_cert = load_ca_certs().get(ca_name)
    if not ca_cert:
        raise ConfigurationError(f"CA cert {ca_name} not found")
    try:
        ca_org_name = ca_cert.issuer.get_attributes_for_oid(OID_ORGANIZATION_NAME)[0].value
    except IndexError:
        logger.error(f"CA certificate {ca_name} has no org name")
        return None
    try:
        supported_ca = SupportedOrgIdCA(ca_org_name)
    except ValueError:
        logger.info(f"CA {ca_name} is not supported for org id extraction")
        return None

    if supported_ca is SupportedOrgIdCA.EXPITRUST:
        org_id = get_org_id_expitrust(cert=cert)
    elif supported_ca is SupportedOrgIdCA.EFOS:
        org_id = get_org_id_efos(cert=cert)
    elif supported_ca is SupportedOrgIdCA.SITHS:
        org_id = get_org_id_siths(cert=cert)
    else:
        logger.info(f"CA {ca_name} / {ca_org_name} is not implemented for org id extraction")
        return None

    if org_id is None:
        return None

    # Add country code as prefix to org id as TLSFED does
    client_country_code = get_oid_for_name(x509_name=cert.subject, oid=OID_COUNTRY_CODE)
    return f"{client_country_code}{org_id}"


def get_org_id_expitrust(cert: Certificate) -> str | None:
    """
    The org number is the serial number of the certificate with prefix 16.
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    serial_number = get_oid_for_name(x509_name=cert.subject, oid=OID_SERIAL_NUMBER)
    if serial_number is None:
        logger.error(f"certificate {cert_fingerprint} has no subject serial number")
        return None
    return serial_number.removeprefix("16")


def get_org_id_siths(cert: Certificate) -> str | None:
    """
    The org number is the first part of the serial number of the certificate with a prefix of SE.
    ex. SE5565594230-AAAA -> 5565594230
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    # Check that the certificate has enhancedKeyUsage clientAuth
    try:
        enhanced_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        if OID_ENHANCED_KEY_USAGE_CLIENT_AUTHENTICATION not in enhanced_key_usage.value:  # type: ignore[operator]
            logger.error(f"certificate {cert_fingerprint} has no enhancedKeyUsage clientAuth")
            return None
    except ExtensionNotFound:
        logger.error(f"certificate {cert_fingerprint} has no enhancedKeyUsage")
        return None

    # Check that the certificate has a subject serial number and parse the org id
    serial_number = get_oid_for_name(x509_name=cert.subject, oid=OID_SERIAL_NUMBER)
    if serial_number is None:
        logger.error(f"certificate {cert_fingerprint} has no subject serial number")
        return None
    org_id, _ = serial_number.split("-")
    return org_id.removeprefix("SE")


def get_org_id_efos(cert: Certificate) -> str:
    """
    The org number is the first part of the serial number of the certificate with a prefix of EFOS16.
    ex. EFOS165565594230-012345 -> 5565594230
    """
    cert_fingerprint = rfc8705_fingerprint(cert)
    # Check that the certificate has a subject serial number and parse the org id
    serial_number = get_oid_for_name(x509_name=cert.subject, oid=OID_SERIAL_NUMBER)
    if serial_number is None:
        logger.error(f"certificate {cert_fingerprint} has no subject serial number")
        return None
    org_id, _ = serial_number.split("-")
    return org_id.removeprefix("EFOS16")


def get_subject_cn(cert: Certificate) -> str | None:
    common_name = get_oid_for_name(x509_name=cert.subject, oid=OID_COMMON_NAME)
    if common_name is None:
        logger.error(f"certificate {rfc8705_fingerprint(cert)} has no subject common name")
    return common_name


def get_subject_c(cert: Certificate) -> str | None:
    country_code = get_oid_for_name(x509_name=cert.subject, oid=OID_COUNTRY_CODE)
    if country_code is None:
        logger.error(f"certificate {rfc8705_fingerprint(cert)} has no subject country code")
    return country_code


def get_subject_o(cert: Certificate) -> str | None:
    org_name = get_oid_for_name(x509_name=cert.subject, oid=OID_ORGANIZATION_NAME)
    if org_name is None:
        logger.error(f"certificate {rfc8705_fingerprint(cert)} has no subject organization name")
    return org_name


def get_issuer_cn(ca_name: str) -> str | None:
    ca_cert = load_ca_certs().get(ca_name)
    if ca_cert is None:
        logger.error(f"CA {ca_name} not found")
        return None
    issuer_common_name = get_oid_for_name(x509_name=ca_cert.subject, oid=OID_COMMON_NAME)
    if issuer_common_name is None:
        logger.error(f"CA {ca_name} has no subject common name")
    return issuer_common_name


def get_oid_for_name(x509_name: Name, oid: ObjectIdentifier) -> str | None:
    try:
        ret = x509_name.get_attributes_for_oid(oid)[0].value
        if isinstance(ret, bytes):
            ret = ret.decode("utf-8")
        return ret
    except IndexError:
        return None


@lru_cache
def load_ca_certs() -> dict[str, Certificate]:
    config = load_config()
    if config.ca_certs_path is None:
        raise ConfigurationError("no CA certs path specified in config")
    certs = {}
    path = Path(config.ca_certs_path)
    for crt in path.glob("**/*.c*"):  # match .crt and .cer files
        if crt.is_dir():
            continue
        try:
            with open(crt, "rb") as f:
                content = f.read()
                try:
                    cert = load_pem_x509_certificate(content)
                except ValueError:
                    cert = load_der_x509_certificate(content)
            if cert_within_validity_period(cert):
                certs[cert.subject.rfc4514_string()] = cert
        except (OSError, ValueError) as e:
            logger.error(f"Failed to load CA cert {crt}: {e}")
    logger.info(f"Loaded {len(certs)} CA certs")
    logger.debug(f"Certs loaded: {certs.keys()}")
    return certs


def load_pem_from_str(cert: str) -> Certificate:
    if not cert.startswith("-----BEGIN CERTIFICATE-----"):
        cert = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
    return load_pem_x509_certificate(cert.encode())


def serialize_certificate(cert: Certificate, encoding: Encoding = Encoding.PEM) -> str:
    public_bytes = cert.public_bytes(encoding=encoding)
    if encoding == Encoding.DER:
        return b64encode(public_bytes).decode("ascii")
    else:
        return public_bytes.decode("ascii")


@lru_cache
def rfc8705_fingerprint(cert: Certificate) -> str:
    return b64encode(cert.fingerprint(algorithm=SHA256())).decode("ascii")
