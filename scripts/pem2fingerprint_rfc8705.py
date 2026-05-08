#!/usr/bin/env python
"""Calculate x5t#S256 (RFC 8705) certificate thumbprint from PEM on stdin."""

import base64
import sys

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate, load_pem_x509_certificate

cert = load_pem_x509_certificate(sys.stdin.buffer.read())


def rfc8705_fingerprint(cert: Certificate) -> str:
    return (
        base64.urlsafe_b64encode(cert.fingerprint(algorithm=SHA256()))
        .decode("ascii")
        .rstrip("=")
    )


print(rfc8705_fingerprint(cert))
