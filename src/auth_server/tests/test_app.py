# -*- coding: utf-8 -*-
import base64
import json
from os import environ
from typing import Optional
from unittest import TestCase, mock
from unittest.mock import AsyncMock

import pkg_resources
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwt
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api

__author__ = 'lundberg'

from auth_server.config import AuthServerConfig, load_config
from auth_server.models.gnap import AccessTokenRequest, AccessTokenRequestFlags, Client, GrantRequest, Key, Proof
from auth_server.models.jose import ECJWK


class MockResponse:
    def __init__(self, content: bytes = b'', status_code: int = 200):
        self._content = content
        self._status_code = status_code

    @property
    def content(self):
        return self._content

    @property
    def status(self):
        return self._status_code

    async def text(self):
        return self._content.decode('utf-8')


class TestApp(TestCase):
    def setUp(self) -> None:
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config = {
            'TESTING': 'true',
            'KEYSTORE': f'{self.datadir}/testing_jwks.json',
            'MDQ_SERVER': 'http://localhost/mdq',
            'AUDIENCE': 'some_audience',
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        with open(f'{self.datadir}/test.cert', 'rb') as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        with open(f'{self.datadir}/test_mdq.xml', 'rb') as f:
            self.mdq_response = f.read()

    def test_read_jwks(self):
        response = self.client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert 'keys' in response.json()
        keys = response.json()['keys']
        assert 1 == len(keys)
        assert ECJWK(**keys[0]).dict(exclude_none=True) == keys[0]

    def test_read_jwk(self):
        response = self.client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        jwk = ECJWK(**response.json())
        assert jwk.dict(exclude_none=True) == response.json()
        assert jwk.kty == 'EC'
        assert jwk.kid == 'default'
        assert jwk.crv == 'P-256'
        assert jwk.x == 'RQ4UriZV8y1g97KSZEDzrEAHeN0K0yvfiNjyNjBsqo8'
        assert jwk.y == 'eRmcA40T-NIFxostV1E7-GDsavCZ3PVAmzDou-uIpvo'

    def test_transaction_test_mode(self):
        environ['TEST_MODE'] = 'yes'
        load_config.cache_clear()  # Clear lru_cache to allow config update

        req = GrantRequest(
            client=Client(key=Key(proof=Proof.TEST)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False

        # Verify token and check claims
        response = self.client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=access_token['value'])
        claims = json.loads(token.claims)
        assert claims['aud'] == 'some_audience'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_transaction_mtls_mdq(self, mock_mdq):
        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_cert_header = {
            'TLS-CLIENT-CERT': base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode('utf-8')
        }
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_cert_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None
