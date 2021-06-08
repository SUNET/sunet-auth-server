# -*- coding: utf-8 -*-
import argparse
import json
from argparse import Namespace
from jwcrypto import jwt
import requests

__author__ = 'lundberg'


def main(args: Namespace):
    response = requests.get(f'{args.server}/.well-known/jwk.json')
    if response.status_code != 200:
        print(f'Failed to get key from server: {response.status_code} {response.text}')
    token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=args.token)
    print('Header:')
    print(json.dumps(json.loads(token.header), indent=4))
    print('Claims:')
    print(json.dumps(json.loads(token.claims), indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Validate and deserialize a JWT token')
    parser.add_argument('--server', '-s', required=True, help='auth server', type=str)
    parser.add_argument('--token', '-t', required=True, help='JWT token', type=str)
    main(args=parser.parse_args())
