# -*- coding: utf-8 -*-
import base64
import json
from datetime import timedelta
from os import environ
from typing import Any, Dict, Optional
from unittest import TestCase, mock
from unittest.mock import AsyncMock

import pkg_resources
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk, jws, jwt
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import load_config
from auth_server.models.gnap import AccessTokenRequest, AccessTokenRequestFlags, Client, GrantRequest, Key, Proof
from auth_server.models.jose import ECJWK, JWSType, SupportedAlgorithms, SupportedHTTPMethods
from auth_server.tests.utils import create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.tls_fed_auth import get_tls_fed_metadata
from auth_server.utils import utc_now

__author__ = 'lundberg'


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
            'AUTH_FLOWS': json.dumps(['FullFlow']),
        }
        environ.update(self.config)
        load_config.cache_clear()  # Clear lru_cache to allow config update
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        with open(f'{self.datadir}/test.cert', 'rb') as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        self.client_cert_str = base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode('utf-8')
        with open(f'{self.datadir}/test_mdq.xml', 'rb') as f:
            self.mdq_response = f.read()
        self.client_jwk = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')

    def _get_access_token_claims(self, access_token: Dict, client: Optional[TestClient]) -> Dict[str, Any]:
        if client is None:
            client = self.client
        response = client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=access_token['value'])
        return json.loads(token.claims)

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

    def test_read_pem(self):
        response = self.client.get("/.well-known/public.pem")
        assert response.status_code == 200

    def test_transaction_test_mode(self):
        environ['AUTH_FLOWS'] = json.dumps(['FullFlow', 'TestFlow'])
        load_config.cache_clear()  # Clear lru_cache to allow config update
        app = init_auth_server_api()  # Instantiate new app with mdq flow
        client = TestClient(app)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof.TEST)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        response = client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=client)
        assert claims['aud'] == 'some_audience'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_transaction_mtls_mdq_with_key_reference(self, mock_mdq):
        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

    def test_transaction_jws(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWS, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        jws_header = {
            'typ': JWSType.JWS,
            'alg': SupportedAlgorithms.ES256.value,
            'kid': self.client_jwk.key_id,
            'htm': SupportedHTTPMethods.POST.value,
            'uri': 'http://testserver/transaction',
            'created': int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk, protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        client_header = {'Content-Type': 'application/jose'}
        response = self.client.post("/transaction", data=data, headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

    def test_transaction_jwsd(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWSD, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        jws_header = {
            'typ': JWSType.JWSD,
            'alg': SupportedAlgorithms.ES256.value,
            'kid': self.client_jwk.key_id,
            'htm': SupportedHTTPMethods.POST.value,
            'uri': 'http://testserver/transaction',
            'created': int(utc_now().timestamp()),
        }
        _jws = jws.JWS(payload=req.json(exclude_unset=True))
        _jws.add_signature(
            key=self.client_jwk, protected=json.dumps(jws_header),
        )
        data = _jws.serialize(compact=True)

        _tmp_jws = jws.JWS()
        _tmp_jws.deserialize(raw_jws=data)
        _tmp_jws.verify(key=self.client_jwk)

        # Remove payload from serialized jws
        header, payload, signature = data.split('.')
        client_header = {'Detached-JWS': f'{header}.{signature}'}

        response = self.client.post("/transaction", json=req.dict(exclude_unset=True), headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_mdq_flow(self, mock_mdq):
        environ['AUTH_FLOWS'] = json.dumps(['MDQFlow'])
        load_config.cache_clear()  # Clear lru_cache to allow config update
        app = init_auth_server_api()  # Instantiate new app with mdq flow
        client = TestClient(app)

        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'),
            access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=client)
        assert claims['entity_id'] == 'https://test.localhost'
        assert claims['scopes'] == ['localhost']

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_tls_fed_flow(self, mock_metadata):
        # Update config and init a new app
        environ['AUTH_FLOWS'] = json.dumps(['TLSFEDFlow'])
        environ['TLS_FED_METADATA'] = json.dumps(
            [{'remote': 'https://metadata.example.com/metadata.jws', 'jwks': f'{self.datadir}/tls_fed_jwks.json'}]
        )
        load_config.cache_clear()  # Clear lru_cache to allow config update
        app = init_auth_server_api()  # Instantiate new app with mdq flow
        client = TestClient(app)

        # Create metadata jws and set it as mock response
        with open(f'{self.datadir}/tls_fed_jwks.json', 'r') as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = 'https://test.localhost'
        metadata = create_tls_fed_metadata(self.datadir, entity_id=entity_id, client_cert=self.client_cert_str)
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key('metadata_signing_key_id'),
            issuer='metdata.example.com',
            expires=timedelta(days=14),
            alg=SupportedAlgorithms.ES256,
        )
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id), access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert access_token['bound'] is False
        assert access_token['value'] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=client)
        assert claims['entity_id'] == 'https://test.localhost'
        assert claims['scopes'] == ['test.localhost']
        assert claims['organization_id'] == 'SE0123456789'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_tls_fed_flow_expired_entity(self, mock_metadata):
        # Update config and init a new app
        environ['AUTH_FLOWS'] = json.dumps(['TLSFEDFlow'])
        environ['TLS_FED_METADATA'] = json.dumps(
            [{'remote': 'https://metadata.example.com/metadata.jws', 'jwks': f'{self.datadir}/tls_fed_jwks.json'}]
        )
        load_config.cache_clear()  # Clear lru_cache to allow config update
        app = init_auth_server_api()  # Instantiate new app with mdq flow
        client = TestClient(app)

        # Create metadata jws and set it as mock response
        with open(f'{self.datadir}/tls_fed_jwks.json', 'r') as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = 'https://test.localhost'
        metadata = create_tls_fed_metadata(self.datadir, entity_id=entity_id, client_cert=self.client_cert_str)
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key('metadata_signing_key_id'),
            issuer='metdata.example.com',
            expires=timedelta(days=-1),
            alg=SupportedAlgorithms.ES256,
        )
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # clear metadata cache
        get_tls_fed_metadata.cache_clear()
        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id), access_token=[AccessTokenRequest(flags=[AccessTokenRequestFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 401
