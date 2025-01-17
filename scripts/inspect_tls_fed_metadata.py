import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import requests
from jwcrypto import jwk, jws

__author__ = "lundberg"


def main(args: argparse.Namespace) -> None:
    # Load jwks
    try:
        with open(args.jwks) as f:
            key_json = f.read()
            jwks = jwk.JWKSet.from_json(key_json)
    except OSError as e:
        print(f"Could not open {args.jwks}: {e}")
        sys.exit(1)
    except jwk.InvalidJWKValue as e:
        print(f"Could not parse key {args.jwks}: {e}")
        print(f"{key_json}")
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
        print(f"Loading jose header: {jose_header}")
        kid = jose_header.get("kid")
        issued_at = jose_header.get("iat")
        expires_at = jose_header.get("exp")
        issuer = jose_header.get("iss")

        # verify jws
        key = jwks.get_key(kid=kid)
        if key is None:
            print(f"key with kid {kid} not found in jwks")
            sys.exit(1)
        _jws.verify(key=key)
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
    metadata = json.loads(_jws.payload)
    print(f'Version: {metadata.get("version")}')
    print()
    if args.entity is not None:
        # print requested entity
        for item in metadata.get("entities", []):
            if item.get("entity_id") == args.entity:
                print(f"Entity ID: {args.entity}")
                print(json.dumps(item, indent=2, ensure_ascii=False))
    else:
        # print full metadata
        print(json.dumps(metadata, indent=2, ensure_ascii=False))
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get and deserialize TLS Federation metadata")
    parser.add_argument("--jwks", "-j", help="path to jwk for the metadata", type=Path, required=True)
    parser.add_argument("--url", "-u", help="URL to the metadata", type=str, required=True)
    parser.add_argument("--entity", "-e", help="entity to output (default: all)", type=str, default=None)
    main(args=parser.parse_args())
