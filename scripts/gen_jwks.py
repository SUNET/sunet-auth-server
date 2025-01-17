import argparse
import json
import sys

from jwcrypto import jwk

__author__ = "lundberg"


def main(args: argparse.Namespace) -> None:
    print("Creating new jwks")
    key = jwk.JWK.generate(kid=args.kid, kty="EC", crv="P-256")
    jwks = jwk.JWKSet()
    jwks.add(key)
    if args.out is not None:
        f = open(args.out, "w")
        msg = f"\njwks written to {f.name}\n"
        indent = None
    else:
        f = sys.stdout
        msg = ""
        indent = 2
    json.dump(jwks.export(as_dict=True), f, indent=indent)
    print(msg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate and deserialize a JWT token")
    parser.add_argument("--kid", "-k", help="key id", type=str, required=True)
    parser.add_argument("--out", "-o", help="out file", default=None, type=str)
    main(args=parser.parse_args())
