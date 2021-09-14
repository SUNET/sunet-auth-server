# -*- coding: utf-8 -*-
import base64
import json
from datetime import timedelta
from os import environ
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Optional
from unittest import TestCase, mock
from unittest.mock import AsyncMock

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jwcrypto import jwk, jws, jwt
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import ClientKey, load_config
from auth_server.models.gnap import AccessTokenFlags, AccessTokenRequest, Client, GrantRequest, Key, Proof
from auth_server.models.jose import ECJWK, JWSType, SupportedAlgorithms, SupportedHTTPMethods
from auth_server.models.status import Status
from auth_server.tests.utils import create_tls_fed_metadata, tls_fed_metadata_to_jws
from auth_server.time_utils import utc_now
from auth_server.tls_fed_auth import get_tls_fed_metadata
from auth_server.utils import get_signing_key, load_jwks

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
        self.datadir = Path(__file__).with_name('data')
        self.config: Dict[str, Any] = {
            'testing': 'true',
            'log_level': 'DEBUG',
            'keystore_path': f'{self.datadir}/testing_jwks.json',
            'signing_key_id': 'test-kid',
            'mdq_server': 'http://localhost/mdq',
            'auth_token_audience': 'some_audience',
            'auth_flows': json.dumps(['FullFlow']),
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

        with open(f'{self.datadir}/test.cert', 'rb') as f:
            self.client_cert = x509.load_pem_x509_certificate(data=f.read())
        self.client_cert_str = base64.b64encode(self.client_cert.public_bytes(encoding=Encoding.DER)).decode('utf-8')
        with open(f'{self.datadir}/test_mdq.xml', 'rb') as f:
            self.mdq_response = f.read()
        self.client_jwk = jwk.JWK.generate(kid='default', kty='EC', crv='P-256')

    def _update_app_config(self, config: Optional[Dict] = None):
        if config is not None:
            environ.clear()
            environ.update(config)
        self._clear_lru_cache()
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    @staticmethod
    def _clear_lru_cache():
        # Clear lru_cache to allow config update
        load_config.cache_clear()
        load_jwks.cache_clear()
        get_signing_key.cache_clear()
        get_tls_fed_metadata.cache_clear()

    def tearDown(self) -> None:
        self.app = None  # type: ignore
        self.client = None  # type: ignore
        self._clear_lru_cache()
        # Clear environment variables
        environ.clear()

    def _get_access_token_claims(self, access_token: Dict, client: Optional[TestClient]) -> Dict[str, Any]:
        if client is None:
            client = self.client
        response = client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwt.JWK(**response.json()), jwt=access_token['value'])
        return json.loads(token.claims)

    def test_get_status_healty(self):
        response = self.client.get("/status/healthy")
        assert response.status_code == 200
        assert 'status' in response.json()
        assert response.json()['status'] == Status.OK.value

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
        assert jwk.kid == 'test-kid'
        assert jwk.crv == 'P-256'
        assert jwk.x == 'RQ4UriZV8y1g97KSZEDzrEAHeN0K0yvfiNjyNjBsqo8'
        assert jwk.y == 'eRmcA40T-NIFxostV1E7-GDsavCZ3PVAmzDou-uIpvo'

    def test_read_pem(self):
        response = self.client.get("/.well-known/public.pem")
        assert response.status_code == 200

    def test_transaction_test_mode(self):
        self.config['auth_flows'] = json.dumps(['FullFlow', 'TestFlow'])
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=Key(proof=Proof.TEST)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['aud'] == 'some_audience'

    def test_config_from_yaml(self):
        # Set absolute path to testing_jwks.json
        config_file_path = f'{self.datadir}/test_config.yaml'
        with open(config_file_path, 'r') as f:
            config = yaml.safe_load(f)
        with NamedTemporaryFile(mode='w') as tf:
            config['auth_server']['keystore_path'] = f'{self.datadir}/testing_jwks.json'
            yaml.dump(config, tf)

            environ['config_file'] = f'{tf.name}'
            environ['config_path'] = 'auth_server'
            self._update_app_config()

        req = GrantRequest(
            client=Client(key=Key(proof=Proof.TEST)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        response = self.client.post("/transaction", json=req.dict(exclude_none=True))
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['aud'] == 'another_audience'
        assert claims['iss'] == 'authserver.local'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_transaction_mtls_mdq_with_key_reference(self, mock_mdq):
        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert access_token['value'] is not None

    def test_transaction_jws(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWS, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
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

        client_header = {'Content-Type': 'application/jose+json'}
        response = self.client.post("/transaction", data=data, headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert access_token['value'] is not None

    def test_transaction_jwsd(self):
        client_key_dict = self.client_jwk.export(as_dict=True)
        client_jwk = ECJWK(**client_key_dict)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof.JWSD, jwk=client_jwk)),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
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

        # Remove payload from serialized jws
        header, payload, signature = data.split('.')
        client_header = {'Detached-JWS': f'{header}..{signature}'}

        response = self.client.post("/transaction", json=req.dict(exclude_unset=True), headers=client_header)

        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert access_token['value'] is not None

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_mdq_flow(self, mock_mdq):
        self.config['auth_flows'] = json.dumps(['MDQFlow'])
        self._update_app_config(config=self.config)

        mock_mdq.return_value = MockResponse(content=self.mdq_response)

        req = GrantRequest(
            client=Client(key='test.localhost'), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert access_token['value'] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['entity_id'] == 'https://test.localhost'
        assert claims['scopes'] == ['localhost']
        assert claims['source'] == 'http://www.swamid.se/'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_tls_fed_flow_remote_metadata(self, mock_metadata):
        self.config['auth_flows'] = json.dumps(['TLSFEDFlow'])
        self.config['tls_fed_metadata'] = json.dumps(
            [{'remote': 'https://metadata.example.com/metadata.jws', 'jwks': f'{self.datadir}/tls_fed_jwks.json'}]
        )
        self._update_app_config(config=self.config)

        # Create metadata jws and set it as mock response
        with open(f'{self.datadir}/tls_fed_jwks.json', 'r') as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = 'https://test.localhost'
        metadata = create_tls_fed_metadata(
            self.datadir, entity_id=entity_id, scopes=['test.localhost'], client_cert=self.client_cert_str
        )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key('metadata_signing_key_id'),
            issuer='metadata.example.com',
            expires=timedelta(days=14),
            alg=SupportedAlgorithms.ES256,
        )
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert access_token['value'] is not None

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['entity_id'] == 'https://test.localhost'
        assert claims['scopes'] == ['test.localhost']
        assert claims['organization_id'] == 'SE0123456789'
        assert claims['source'] == 'metadata.example.com'

    def test_tls_fed_flow_local_metadata(self):
        # Create metadata jws and save it as a temporary file
        with open(f'{self.datadir}/tls_fed_jwks.json', 'r') as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = 'https://test.localhost'
        metadata = create_tls_fed_metadata(
            self.datadir, entity_id=entity_id, scopes=['test.localhost'], client_cert=self.client_cert_str
        )
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key('metadata_signing_key_id'),
            issuer='metadata.example.com',
            expires=timedelta(days=14),
            alg=SupportedAlgorithms.ES256,
            compact=False,
        )

        with NamedTemporaryFile() as f:
            f.write(metadata_jws)
            f.flush()
            self.config['auth_flows'] = json.dumps(['TLSFEDFlow'])
            self.config['tls_fed_metadata'] = json.dumps(
                [{'local': f'{f.name}', 'jwks': f'{self.datadir}/tls_fed_jwks.json'}]
            )
            self._update_app_config(config=self.config)

            # Start transaction
            req = GrantRequest(
                client=Client(key=entity_id), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
            )
            client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
            response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
            assert response.status_code == 200
            assert 'access_token' in response.json()
            access_token = response.json()['access_token']
            assert AccessTokenFlags.BEARER.value in access_token['flags']
            assert access_token['value'] is not None

            # Verify token and check claims
            claims = self._get_access_token_claims(access_token=access_token, client=self.client)
            assert claims['entity_id'] == 'https://test.localhost'
            assert claims['scopes'] == ['test.localhost']
            assert claims['organization_id'] == 'SE0123456789'
            assert claims['source'] == 'metadata.example.com'

    @mock.patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    def test_tls_fed_flow_expired_entity(self, mock_metadata):
        self.config['auth_flows'] = json.dumps(['TLSFEDFlow'])
        self.config['tls_fed_metadata'] = json.dumps(
            [{'remote': 'https://metadata.example.com/metadata.jws', 'jwks': f'{self.datadir}/tls_fed_jwks.json'}]
        )
        self._update_app_config(config=self.config)

        # Create metadata jws and set it as mock response
        with open(f'{self.datadir}/tls_fed_jwks.json', 'r') as f:
            tls_fed_jwks = jwk.JWKSet()
            tls_fed_jwks.import_keyset(f.read())

        entity_id = 'https://test.localhost'
        metadata = create_tls_fed_metadata(Path(self.datadir), entity_id=entity_id, client_cert=self.client_cert_str)
        metadata_jws = tls_fed_metadata_to_jws(
            metadata,
            key=tls_fed_jwks.get_key('metadata_signing_key_id'),
            issuer='metadata.example.com',
            expires=timedelta(days=-1),
            alg=SupportedAlgorithms.ES256,
        )
        mock_metadata.return_value = MockResponse(content=metadata_jws)

        # clear metadata cache
        get_tls_fed_metadata.cache_clear()
        # Start transaction
        req = GrantRequest(
            client=Client(key=entity_id), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 401

    def test_config_flow(self):
        self.config['auth_flows'] = json.dumps(['TestFlow', 'ConfigFlow'])
        del self.config['auth_token_audience']  # auth_token_audience defaults to None
        client_key = ClientKey.parse_obj(
            {'proof': Proof.MTLS, 'cert': self.client_cert_str, 'claims': {'test_claim': 'test_claim_value'}}
        )
        key_reference = 'test_key_ref'
        self.config['client_keys'] = json.dumps({key_reference: client_key.dict(exclude_unset=True)})
        self._update_app_config(config=self.config)

        req = GrantRequest(
            client=Client(key=key_reference), access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {'TLS-CLIENT-CERT': self.client_cert_str}
        response = self.client.post("/transaction", json=req.dict(exclude_none=True), headers=client_header)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['sub'] == key_reference
        assert claims['test_claim'] == 'test_claim_value'
        assert claims['source'] == 'config'
        assert 'aud' not in claims

    def test_requested_access_in_jwt(self):
        self.config['auth_flows'] = json.dumps(['TestFlow'])
        self._update_app_config(config=self.config)

        grant_request = {
            'access_token': {
                'flags': ['bearer'],
                'access': ['test_access_string', {'type': 'test_access', 'scope': 'a_scope'}],
            },
            'client': {'key': {'proof': 'test'}},
        }

        response = self.client.post("/transaction", json=grant_request)
        assert response.status_code == 200
        assert 'access_token' in response.json()
        access_token = response.json()['access_token']
        assert AccessTokenFlags.BEARER.value in access_token['flags']
        assert 'access' in access_token
        assert 'test_access_string' in access_token['access']
        for item in access_token['access']:
            if isinstance(item, dict):
                assert 'scope' in item
                assert item['scope'] == 'a_scope'

        # Verify token and check claims
        claims = self._get_access_token_claims(access_token=access_token, client=self.client)
        assert claims['aud'] == 'some_audience'
        assert 'requested_access' in claims
        assert 'test_access_string' in claims['requested_access']
        for item in claims['requested_access']:
            if isinstance(item, dict):
                assert 'scope' in item
                assert item['scope'] == 'a_scope'
