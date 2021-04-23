# -*- coding: utf-8 -*-
import base64
import json
from os import environ
from unittest import TestCase, mock
from unittest.mock import AsyncMock

import pkg_resources
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk, jwt
from jwcrypto.jws import JWS
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api

__author__ = 'lundberg'

from auth_server.config import load_config
from auth_server.models.gnap import AccessTokenRequest, AccessTokenRequestFlags, Client, GrantRequest, Key, Proof
from auth_server.models.jose import ECJWK, SupportedAlgorithms, SupportedHTTPMethods
from auth_server.utils import utc_now


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
            'LOG_LEVEL': 'DEBUG',
            'KEYSTORE': f'{self.datadir}/testing_jwks.json',
            'MDQ_SERVER': 'http://localhost/mdq',
            'AUTH_TOKEN_AUDIENCE': 'some_audience',
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        with open(f'{self.datadir}/test.cert', 'rb') as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        with open(f'{self.datadir}/test_mdq.xml', 'rb') as f:
            self.mdq_response = f.read()
        self.client_jwk = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')

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
    def test_transaction_mtls_mdq_with_key_reference(self, mock_mdq):
        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_header = {
            'TLS-CLIENT-CERT': base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode('utf-8')
        }
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

    @staticmethod
    def _create_at_hash(grant_request: GrantRequest, hash_alg: HashAlgorithm):
        access_token_str = json.dumps(grant_request.dict(exclude_unset=True)['access_token'])
        digest = Hash(hash_alg)
        digest.update(access_token_str.encode())
        digest_bytes = digest.finalize()
        return base64.b64encode(digest_bytes[: hash_alg.digest_size // 2]).decode('utf-8')

    def test_transaction_jsw(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWS, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        at_hash = self._create_at_hash(req, SHA256())
        jws_headers = {
            'alg': SupportedAlgorithms.ES256.value,
            'kid': self.client_jwk.key_id,
            'htm': SupportedHTTPMethods.POST.value,
            'htu': 'http://testserver/transaction',
            'ts': int(utc_now().timestamp()),
            'at_hash': at_hash,
        }
        jws = JWS(payload=req.json(exclude_unset=True))
        jws.add_signature(
            key=self.client_jwk, protected=json.dumps(jws_headers),
        )
        data = jws.serialize(compact=True)

        client_header = {'Content-Type': 'application/jose'}
        response = self.client.post("/transaction", data=data, headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

    # TODO: Something strange about detached jws verification
    @pytest.mark.skip(reason="Something strange about detached jws verification")
    def test_transaction_jswd(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWSD, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        at_hash = self._create_at_hash(req, SHA256())
        jws_headers = {
            'alg': SupportedAlgorithms.ES256.value,
            'kid': self.client_jwk.key_id,
            'htm': SupportedHTTPMethods.POST.value,
            'htu': 'http://testserver/transaction',
            'ts': int(utc_now().timestamp()),
            'at_hash': at_hash,
            'b64': False,
            'crit': ['b64'],
        }
        jws = JWS(payload=req.json(exclude_unset=True))
        jws.add_signature(
            key=self.client_jwk, protected=json.dumps(jws_headers),
        )
        data = jws.serialize(compact=True)
        # Remove payload from serialized jws
        data = f'{data.split(".")[0]}..{data.split(".")[2]}'

        client_header = {'Detached-JWS': data}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None
