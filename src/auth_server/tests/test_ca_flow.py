# -*- coding: utf-8 -*-
import json
from os import environ
from pathlib import Path
from typing import Any, Dict, Optional
from unittest import IsolatedAsyncioTestCase, TestCase

from cryptography import x509
from cryptography.x509 import Certificate
from httpx import Response
from jwcrypto import jwk, jwt
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.cert_utils import (
    cert_signed_by_ca,
    cert_within_validity_period,
    get_subject_cn,
    is_cert_revoked,
    load_ca_certs,
    rfc8705_fingerprint,
    serialize_certificate,
)
from auth_server.config import load_config
from auth_server.db.transaction_state import AuthSource
from auth_server.models.gnap import AccessTokenFlags, AccessTokenRequest, Client, GrantRequest, Key, Proof, ProofMethod
from auth_server.tls_fed_auth import get_tls_fed_metadata
from auth_server.utils import get_signing_key, load_jwks

__author__ = "lundberg"


class MockResponse:
    def __init__(self, content: bytes = b"", status_code: int = 200):
        self._content = content
        self._status_code = status_code
        self.accessed_status = 0

    @property
    def content(self):
        return self._content

    @property
    def status(self):
        self.accessed_status += 1
        return self._status_code

    async def text(self):
        return self._content.decode("utf-8")


class TestAuthServer(TestCase):
    def setUp(self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.config: Dict[str, Any] = {
            "testing": "true",
            "log_level": "DEBUG",
            "keystore_path": f"{self.datadir}/testing_jwks.json",
            "ca_certs_path": f"{self.datadir}/ca/ca_cert/",
            "signing_key_id": "test-kid",
            "auth_token_issuer": "http://testserver",
            "auth_token_audience": "some_audience",
            "auth_flows": json.dumps(["CAFlow"]),
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    def _update_app_config(self, config: Optional[Dict] = None):
        if config is not None:
            environ.clear()
            environ.update(config)
        self._clear_lru_cache()
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    def _load_cert(self, filename: str) -> Certificate:
        with open(f"{self.datadir}/ca/{filename}", "rb") as f:
            cert = x509.load_pem_x509_certificate(data=f.read())
        return cert

    def _get_access_token_claims(self, access_token: Dict, client: Optional[TestClient]) -> Dict[str, Any]:
        if client is None:
            client = self.client
        response = client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwk.JWK(**response.json()), jwt=access_token["value"])
        return json.loads(token.claims)

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

    def test_load_ca_certs(self):
        ca_certs = load_ca_certs()
        assert len(ca_certs) == 3

    def test_cert_signed_by_ca(self):
        parameters = [
            ("bolag_a.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE"),
            ("bolag_b.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE"),
            ("bolag_c.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE"),
            ("bolag_e.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE"),
        ]
        for cert_name, expected_ca_name in parameters:
            cert = self._load_cert(filename=cert_name)
            ca_name = cert_signed_by_ca(cert)
            assert ca_name == expected_ca_name

    def test_cert_within_validity_period(self):
        parameters = [
            ("bolag_a.crt", True),
            ("bolag_b.crt", True),
            ("bolag_c.crt", False),
            ("bolag_e.crt", False),
        ]
        for cert_name, within_validity_period in parameters:
            cert = self._load_cert(filename=cert_name)
            assert (
                cert_within_validity_period(cert) is within_validity_period
            ), f"{cert_name} should be {not within_validity_period}"

    def _do_mtls_transaction(self, cert: Certificate) -> Response:
        client_cert_str = serialize_certificate(cert=cert)
        req = GrantRequest(
            client=Client(key=Key(proof=Proof(method=ProofMethod.MTLS), cert_S256=rfc8705_fingerprint(cert=cert))),
            access_token=[AccessTokenRequest(flags=[AccessTokenFlags.BEARER])],
        )
        client_header = {"Client-Cert": client_cert_str}
        return self.client.post("/transaction", json=req.model_dump(exclude_none=True), headers=client_header)

    def test_mtls_transaction(self):
        parameters = [
            ("bolag_a.crt", True, "165560000167"),
            ("bolag_b.crt", False, "client certificate revoked"),
            ("bolag_c.crt", False, "client certificate expired or not yet valid"),
            ("bolag_e.crt", False, "client certificate expired or not yet valid"),
        ]
        for cert_name, expect_success, expected_result in parameters:
            cert = self._load_cert(filename=cert_name)
            response = self._do_mtls_transaction(cert=cert)

            if expect_success:
                assert response.status_code == 200
                assert "access_token" in response.json()
                access_token = response.json()["access_token"]
                assert AccessTokenFlags.BEARER.value in access_token["flags"]
                assert access_token["value"] is not None
                # Verify token and check claims
                claims = self._get_access_token_claims(access_token=access_token, client=self.client)
                assert claims["auth_source"] == AuthSource.CA
                assert claims is not None
                assert claims["organization_id"] == expected_result, f"{cert_name} has wrong org id"
                assert claims["common_name"] == get_subject_cn(cert=cert), f"{cert_name} has wrong common name"
                assert claims["source"] is not None
            else:
                assert response.status_code == 401
                assert response.json()["detail"] == expected_result


class TestAuthServerAsync(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.config: Dict[str, Any] = {
            "testing": "true",
            "log_level": "DEBUG",
            "keystore_path": f"{self.datadir}/testing_jwks.json",
            "ca_certs_path": f"{self.datadir}/ca/ca_cert/",
            "signing_key_id": "test-kid",
            "auth_token_issuer": "http://testserver",
            "auth_token_audience": "some_audience",
            "auth_flows": json.dumps(["TestFlow"]),
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    def _load_cert(self, filename: str) -> Certificate:
        with open(f"{self.datadir}/ca/{filename}", "rb") as f:
            cert = x509.load_pem_x509_certificate(data=f.read())
        return cert

    async def test_cert_is_revoked(self):
        parameters = [
            ("bolag_a.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE", False),
            ("bolag_b.crt", "CN=ExpiTrust Test CA v8,O=Expisoft AB,C=SE", True),
        ]
        for cert_name, ca_name, revoked_status in parameters:
            cert = self._load_cert(filename=cert_name)
            assert await is_cert_revoked(cert, ca_name) is revoked_status, f"{cert_name} should be {not revoked_status}"
