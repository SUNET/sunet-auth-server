from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import requests
from jwcrypto import jwk, jws

# add auth_server to sys path for import of models
repo_root = Path(__file__).absolute().parent.parent
sys.path.append(f"{repo_root}/src/")


from auth_server.models.tls_fed_metadata import Entity, Model  # noqa: E402

__author__ = "lundberg"


def main(args: argparse.Namespace) -> None:
    # Load jwks
    try:
        with open(args.jwks) as f:
            jwks = jwk.JWKSet.from_json(f.read())
    except OSError as e:
        print(f"Could not open {args.jwks}: {e}")
        sys.exit(1)

    # Retrieve metadata
    try:
        response = requests.get(args.url)
    except requests.exceptions.RequestException as e:
        print(f"Could not get {args.url}: {e}")
        sys.exit(1)

    # Deserialize and validate metadata
    _jws = jws.JWS()
    try:
        # deserialize jws
        _jws.deserialize(raw_jws=response.text)
        jose_header = {}
        if isinstance(_jws.jose_header, list):
            jose_header = _jws.jose_header[0]
        elif isinstance(_jws.jose_header, dict):
            jose_header = _jws.jose_header

        # load header values
        kid = jose_header.get("kid")
        issued_at = jose_header.get("iat")
        expires_at = jose_header.get("exp")
        issuer = jose_header.get("iss")

        # verify jws
        _jws.verify(key=jwks.get_key(kid=kid))
    except (jws.InvalidJWSObject, IndexError) as e:
        print(f"metadata could not be deserialized: {e}")
        sys.exit(1)
    except jws.InvalidJWSSignature as e:
        print(f"metadata could not be verified: {e}")
        sys.exit(1)

    # print output
    print()
    print(f"Metadata for issuer {issuer}:")
    print(f"Issued at: {datetime.fromtimestamp(issued_at)}. Expires at: {datetime.fromtimestamp(expires_at)}")
    print()
    full_parse_fail = False
    try:
        metadata = Model.parse_raw(_jws.payload, encoding="utf-8")
        print(f"Version: {metadata.version} parsed OK")
    except Exception as e:
        full_parse_fail = True
        print(f"Error validating metadata: {e}")
        print()

    if full_parse_fail:
        print("Trying to parse entities one by one")
        for item in json.loads(_jws.payload)["entities"]:
            try:
                Entity.parse_obj(item)
            except Exception as e:
                print(f'Failed to parse: {item["entity_id"]}: {e}')

    print()

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get and deserialize TLS Federation metadata")
    parser.add_argument("--jwks", "-j", help="path to jwk for the metadata", type=Path, required=True)
    parser.add_argument("--url", "-u", help="URL to the metadata", type=str, required=True)
    parser.add_argument("--entity", "-e", help="entity to output (default: all)", type=str, default=None)
    main(args=parser.parse_args())
