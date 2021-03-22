# -*- coding: utf-8 -*-
import base64
import json
from typing import Optional
from unittest import TestCase, mock
from unittest.mock import AsyncMock

import pkg_resources
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwt
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.models import ECJWK, AuthRequest, Key, Proof, Resources

__author__ = 'lundberg'


class MockResponse:
    def __init__(self, content: bytes = b'', json_data: Optional[dict] = None, status_code: int = 200):
        self._content = content
        self._json_data = json_data
        self._status_code = status_code

    @property
    def content(self):
        return self._content

    @property
    def json(self):
        return self._json_data

    def raise_for_status(self):
        pass

    @property
    def status(self):
        return self._status_code

    async def text(self):
        return self._content.decode('utf-8')


class TestApp(TestCase):
    def setUp(self) -> None:
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config = {
            'testing': True,
            'keystore_path': f'{self.datadir}/testing_jwks.json',
            'mdq_server': 'http://localhost/mdq',
            'audience': 'some_audience',
        }
        self.app = init_auth_server_api(test_config=self.config)
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
        assert 'x' in jwk.dict(exclude_none=True)
        assert 'y' in jwk.dict(exclude_none=True)

    def test_transaction_test_mode(self):
        self.app.state.config.test_mode = True

        req = AuthRequest(keys=Key(proof=Proof.TEST, kid='some_kid'), resources=Resources(origins=['test']))
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['type'] == 'bearer'

        # Verify token and check claims
        response = self.client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=access_token['value'])
        claims = json.loads(token.claims)
        assert claims['aud'] == 'some_audience'
        assert claims['origins'] == ['test']

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_transaction_mtls_mdq(self, mock_mdq):
        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = AuthRequest(keys=Key(proof=Proof.MTLS, kid='test.localhost'), resources=Resources(origins=['test']))
        client_cert_header = {
            'SSL-CLIENT-CERT': base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode('utf-8')
        }
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_cert_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['type'] == 'bearer'
        assert access_token['value'] is not None
