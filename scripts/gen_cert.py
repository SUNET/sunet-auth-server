import argparse
import os
import sys
from base64 import b64encode
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import NameOID

__author__ = "lundberg"


def main(args: argparse.Namespace) -> None:
    # Generate key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    passphrase = serialization.NoEncryption()
    if args.passphrase is not None:
        passphrase = serialization.BestAvailableEncryption(args.passphrase.encode())
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=passphrase,
    )

    # Write key
    if args.out is not None:
        key_path = f"{args.out}{os.sep}{args.common_name}.key"
        if os.path.exists(key_path):
            sys.stderr.write(f"{key_path} already exists\n")
            sys.exit(1)
        with open(key_path, "wb") as f:
            f.write(private_bytes)
    else:
        sys.stdout.writelines(f"Private key for {args.common_name}:\n")
        sys.stdout.writelines(private_bytes.decode("utf-8"))
        sys.stdout.writelines("\n")

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, args.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, args.common_name),
        ]
    )
    alt_names = [x509.DNSName(alt_name) for alt_name in args.alt_names]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=args.expires))
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )
    public_bytes = cert.public_bytes(serialization.Encoding.PEM)
    # Write certificate
    if args.out is not None:
        cert_path = f"{args.out}{os.sep}{args.common_name}.crt"
        if os.path.exists(cert_path):
            sys.stderr.write(f"{cert_path} already exists\n")
            sys.exit(1)
        with open(cert_path, "wb") as f:
            f.write(public_bytes)
    else:
        sys.stdout.writelines(f"Certificate for {args.common_name}:\n")
        sys.stdout.writelines(public_bytes.decode("utf-8"))
        sys.stdout.writelines("\n")

    # Print additional info
    sys.stdout.writelines("cert#S256 fingerprint:\n")
    sys.stdout.writelines(b64encode(cert.fingerprint(algorithm=SHA256())).decode("utf-8"))
    sys.stdout.writelines("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate key and cert")
    parser.add_argument("--country", "-c", default="SE", help="country (default: SE)", type=str)
    parser.add_argument("--province", "-p", default="Stockholm", help="province (default: Stockholm)", type=str)
    parser.add_argument("--locality", "-l", default="Stockholm", help="locality (default: Stockholm)", type=str)
    parser.add_argument("--organization", "-o", default="Sunet", help="organization (default: Sunet)", type=str)
    parser.add_argument("--common-name", "-cn", help="common name", type=str, required=True)
    parser.add_argument("--expires", "-e", default=365, help="expires in X days (default: 365)", type=int)
    parser.add_argument("--alt-names", help="alternative names", nargs="*", default=[], type=str)
    parser.add_argument("--passphrase", help="passphrase for key", nargs="?", default=None, type=str)
    parser.add_argument("--out", help="output directory", nargs="?", default=None, type=str)
    main(args=parser.parse_args())
