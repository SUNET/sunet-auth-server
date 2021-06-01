# -*- coding: utf-8 -*-
import json
import sys

from jwcrypto import jwk

__author__ = 'lundberg'


def main(path: str = None):
    print('Creating new jwks')
    key = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')
    jwks = jwk.JWKSet()
    jwks.add(key)
    if path is not None:
        f = open(path, 'w')
        msg = f'\njwks written to {f.name}\n'
        indent = None
    else:
        f = sys.stdout
        msg = ''
        indent = 2
    json.dump(jwks.export(as_dict=True), f, indent=indent)
    print(msg)


if __name__ == '__main__':
    path = None
    if len(sys.argv) == 2:
        path = sys.argv[1]
    main(path=path)
