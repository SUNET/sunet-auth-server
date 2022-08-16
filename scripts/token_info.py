# -*- coding: utf-8 -*-
import sys
import argparse
import json
from argparse import Namespace
from jwcrypto import jwt
import requests

__author__ = 'lundberg'


def main(args: Namespace):
    if args.infile:
        lines = args.infile.readlines()
        data_in = ''.join(lines)
        data_in = ''.join(data_in.split())  # remove whitespace
    elif args.token:
        data_in = args.token
    if not data_in:
        print('Missing token')
        sys.exit(1)
    print(data_in)
    response = requests.get(f'{args.server}/.well-known/jwk.json')
    if response.status_code != 200:
        print(f'Failed to get key from server: {response.status_code} {response.text}')
    token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=data_in)
    print('Header:')
    print(json.dumps(json.loads(token.header), indent=4))
    print('Claims:')
    print(json.dumps(json.loads(token.claims), indent=4))
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Validate and deserialize a JWT token')
    parser.add_argument('--server', '-s', required=True, help='auth server', type=str)
    parser.add_argument('--token', '-t', required=False, help='JWT token', type=str)
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    main(args=parser.parse_args())
