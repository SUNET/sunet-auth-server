import asyncio
import base64
import hashlib
import json
import re
import uuid
from datetime import timedelta
from os import environ
from pathlib import Path
from typing import Any, Self
from unittest import IsolatedAsyncioTestCase, TestCase, mock
from unittest.mock import MagicMock

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from http_message_signatures import HTTPMessageSigner, MappingKeyResolver
from http_message_signatures.algorithms import ECDSA_P256_SHA256
from jwcrypto import jwk, jws, jwt
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import ValidationError
from starlette.requests import Request
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import ConfigurationError, load_config
from auth_server.context import ContextRequest
from auth_server.db.proof_nonce import InMemoryProofNonceStore, ProofNonceDB, clear_proof_nonce_cache
from auth_server.db.transaction_state import TransactionState
from auth_server.flows import NextFlowException, OnlyMTLSProofFlow
from auth_server.models.gnap import Key, ProofMethod
from auth_server.models.jose import OKPJWK
from auth_server.proof.common import get_target_uri
from auth_server.saml2 import AuthnInfo, NameID, SAMLAttributes, SessionInfo
from auth_server.testing import MongoTemporaryInstance
from auth_server.tests import test_app
from auth_server.time_utils import utc_now

__author__ = "lundberg"

BASE_URL = "http://testserver"

# RFC 9421 algorithm name for each key type used in the tests
ALGS = {
    "ES256": "ecdsa-p256-sha256",
    "ES384": "ecdsa-p384-sha384",
    "RS256": "rsa-v1_5-sha256",
    "PS512": "rsa-pss-sha512",
    "EdDSA": "ed25519",
}


def generate_key(jws_alg: str, kid: str | None = "client-key") -> jwk.JWK:
    kwargs: dict[str, Any] = {"kid": kid} if kid is not None else {}
    if jws_alg == "ES256":
        return jwk.JWK.generate(kty="EC", crv="P-256", **kwargs)
    elif jws_alg == "ES384":
        return jwk.JWK.generate(kty="EC", crv="P-384", **kwargs)
    elif jws_alg in ("RS256", "PS512"):
        return jwk.JWK.generate(kty="RSA", size=2048, **kwargs)
    elif jws_alg == "EdDSA":
        return jwk.JWK.generate(kty="OKP", crv="Ed25519", **kwargs)
    raise ValueError(jws_alg)


def public_jwk(key: jwk.JWK, alg: str | None = None, kid: str | None = "keep") -> dict[str, Any]:
    data = key.export_public(as_dict=True)
    if alg is not None:
        data["alg"] = alg
    if kid != "keep":
        data.pop("kid", None)
        if kid is not None:
            data["kid"] = kid
    return data


def content_digest(body: bytes, alg: str = "sha-256") -> str:
    digest = hashlib.new(alg.replace("-", ""), body).digest()
    return f"{alg}=:{base64.b64encode(digest).decode()}:"


def raw_sign(key: jwk.JWK, httpsig_alg: str, base: bytes) -> bytes:
    private_key = key.get_op_key("sign")
    if httpsig_alg in ("ecdsa-p256-sha256", "ecdsa-p384-sha384"):
        size, hash_alg = (32, hashes.SHA256()) if httpsig_alg == "ecdsa-p256-sha256" else (48, hashes.SHA384())
        r, s = decode_dss_signature(private_key.sign(base, ec.ECDSA(hash_alg)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif httpsig_alg == "rsa-v1_5-sha256":
        return private_key.sign(base, padding.PKCS1v15(), hashes.SHA256())
    elif httpsig_alg == "rsa-pss-sha512":
        return private_key.sign(base, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
    elif httpsig_alg == "ed25519":
        return private_key.sign(base)
    raise ValueError(httpsig_alg)


def make_signature(
    key: jwk.JWK,
    httpsig_alg: str,
    method: str,
    url: str,
    headers: dict[str, str],
    components: list[str],
    label: str = "sig1",
    created: int | None = None,
    keyid: str | None = None,
    tag: str | None = "gnap",
    nonce: str | None = None,
    omit_nonce: bool = False,
    expires: int | None = None,
    include_alg: bool = False,
    include_created: bool = True,
) -> dict[str, str]:
    """Hand rolled RFC 9421 signer, so the tests do not depend on the library used by the server"""
    lower_headers = {name.lower(): value for name, value in headers.items()}
    params = ""
    if include_created:
        params += f";created={created if created is not None else int(utc_now().timestamp())}"
    if expires is not None:
        params += f";expires={expires}"
    if nonce is None and not omit_nonce:
        nonce = uuid.uuid4().hex  # nonces are required by default
    if nonce is not None:
        params += f';nonce="{nonce}"'
    params += f';keyid="{keyid if keyid is not None else key.key_id}"'
    if include_alg:
        params += f';alg="{httpsig_alg}"'
    if tag is not None:
        params += f';tag="{tag}"'
    signature_params = "(" + " ".join(f'"{c}"' for c in components) + ")" + params
    lines = []
    for component in components:
        if component == "@method":
            value = method
        elif component == "@target-uri":
            value = url
        else:
            value = lower_headers[component]
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {signature_params}')
    signature = raw_sign(key, httpsig_alg, "\n".join(lines).encode())
    return {
        "Signature-Input": f"{label}={signature_params}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode()}:",
    }


def combine(*signatures: dict[str, str]) -> dict[str, str]:
    return {
        "Signature-Input": ", ".join(s["Signature-Input"] for s in signatures),
        "Signature": ", ".join(s["Signature"] for s in signatures),
    }


class TestHttpsig(TestCase):
    def _get_access_token_claims(self: Self, access_token: dict[str, Any]) -> dict[str, Any]:
        response = self.client.get("/.well-known/jwk.json")
        assert response.status_code == 200
        token = jwt.JWT(key=jwk.JWK(**response.json()), jwt=access_token["value"])
        return json.loads(token.claims)

    def _fake_saml_authentication(self: Self, transaction_id: str) -> None:
        doc = self.transaction_states.find_one({"transaction_id": transaction_id})
        assert doc is not None  # please mypy
        transaction_state = TransactionState(**doc)
        transaction_state.saml_session_info = SessionInfo(
            issuer="https://idp.example.com",
            attributes=SAMLAttributes(eppn="test@example.com", unique_id="test@example.com"),
            name_id=NameID(
                format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                sp_name_qualifier="http://test.localhost/saml2-metadata",
                id="some_id",
                name_qualifier="some_name_qualifer",
                sp_provided_id="some_other_id",
            ),
            authn_info=[
                AuthnInfo(authn_class="https://refeds.org/profile/mfa", authn_authority=[], authn_instant=utc_now())
            ],
        )
        self.transaction_states.replace_one(
            {"transaction_id": transaction_id}, transaction_state.dict(exclude_none=True)
        )

    def _do_consent(self: Self, transaction_id: str) -> httpx.Response:
        """load the consent screen and answer it the way a user would"""
        response = self.client.get(f"/interaction/redirect/{transaction_id}")
        assert response.status_code == 200
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
        assert match is not None, "no csrf token found in the consent page"
        return self.client.post(
            f"/interaction/consent/{transaction_id}", data={"csrf_token": match.group(1), "decision": "approve"}
        )

    def setUp(self: Self) -> None:
        self.datadir = Path(__file__).with_name("data")
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.config: dict[str, Any] = {
            "testing": "true",
            "log_level": "DEBUG",
            "keystore_path": f"{self.datadir}/testing_jwks.json",
            "signing_key_id": "test-kid",
            "auth_token_issuer": "http://testserver",
            "auth_token_audience": "some_audience",
            "auth_flows": json.dumps(["TestFlow"]),
            "mongo_uri": self.mongo_db.uri,
            "logging_config": json.dumps({"loggers": {"pymongo": {"level": "INFO"}}}),
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        self.transaction_states = self.mongo_db.conn["auth_server"]["transaction_states"]
        self.proof_nonces = self.mongo_db.conn["auth_server"]["proof_nonces"]
        self.key = generate_key("ES256")

    def tearDown(self: Self) -> None:
        self.app = None  # type: ignore
        self.client = None  # type: ignore
        test_app.TestAuthServer._clear_lru_cache()
        self.transaction_states.drop()
        self.proof_nonces.drop()
        clear_proof_nonce_cache()
        environ.clear()

    def _update_app_config(self: Self, **config: Any) -> None:
        self.config.update(config)
        environ.clear()
        environ.update(self.config)
        test_app.TestAuthServer._clear_lru_cache()
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    # helpers

    @staticmethod
    def _grant_body(
        key_dict: dict[str, Any] | str,
        proof: str | dict[str, Any] = "httpsig",
        interact: bool = False,
    ) -> bytes:
        client_key: dict[str, Any] | str
        if isinstance(key_dict, str):
            client_key = key_dict  # key reference
        else:
            client_key = {"proof": proof, "jwk": key_dict}
        grant: dict[str, Any] = {"access_token": {"flags": ["bearer"]}, "client": {"key": client_key}}
        if interact:
            grant["interact"] = {"start": ["redirect"]}
        # not the most compact form, the digest has to be calculated over exactly what is sent
        return json.dumps(grant, indent=2).encode()

    def _signed_headers(
        self: Self,
        method: str,
        url: str,
        body: bytes | None,
        alg: str = "ES256",
        key: jwk.JWK | None = None,
        extra_headers: dict[str, str] | None = None,
        components: list[str] | None = None,
        digest_alg: str = "sha-256",
        sign_url: str | None = None,
        **kwargs: Any,
    ) -> dict[str, str]:
        key = key or self.key
        headers: dict[str, str] = dict(extra_headers or {})
        if body:
            headers["Content-Type"] = "application/json"
            headers["Content-Digest"] = content_digest(body, digest_alg)
        if components is None:
            components = ["@method", "@target-uri"]
            if body:
                components += ["content-digest"]
            if "Authorization" in headers:
                components += ["authorization"]
        headers.update(
            make_signature(
                key=key,
                httpsig_alg=ALGS[alg],
                method=method,
                url=sign_url or url,
                headers=headers,
                components=components,
                **kwargs,
            )
        )
        return headers

    def _post_transaction(
        self: Self,
        body: bytes,
        alg: str = "ES256",
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        if headers is None:
            headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body, alg=alg, **kwargs)
        return self.client.post("/transaction", content=body, headers=headers)

    def _assert_invalid_client(self: Self, response: httpx.Response) -> None:
        assert response.status_code == 400, response.text
        assert response.json()["error"]["code"] == "invalid_client"

    # valid signatures

    def test_transaction_algorithms_string_form(self: Self) -> None:
        # in the string form the algorithm comes from the alg of the key
        for jws_alg in ALGS:
            with self.subTest(alg=jws_alg):
                key = generate_key(jws_alg)
                body = self._grant_body(public_jwk(key, alg=jws_alg))
                response = self._post_transaction(body, alg=jws_alg, key=key)
                assert response.status_code == 200, response.text
                assert "access_token" in response.json()

    def test_transaction_algorithms_object_form(self: Self) -> None:
        for jws_alg, httpsig_alg in ALGS.items():
            with self.subTest(alg=jws_alg):
                key = generate_key(jws_alg)
                proof = {"method": "httpsig", "alg": httpsig_alg}
                body = self._grant_body(public_jwk(key), proof=proof)
                response = self._post_transaction(body, alg=jws_alg, key=key)
                assert response.status_code == 200, response.text

    def test_transaction_object_form_with_matching_key_alg(self: Self) -> None:
        proof = {"method": "httpsig", "alg": "ecdsa-p256-sha256"}
        body = self._grant_body(public_jwk(self.key, alg="ES256"), proof=proof)
        assert self._post_transaction(body).status_code == 200

    def test_transaction_content_digest_alg_sha512(self: Self) -> None:
        proof = {"method": "httpsig", "alg": "ecdsa-p256-sha256", "content-digest-alg": "sha-512"}
        body = self._grant_body(public_jwk(self.key), proof=proof)
        response = self._post_transaction(body, digest_alg="sha-512")
        assert response.status_code == 200, response.text

    def test_transaction_sha256_digest_rejected_when_sha512_declared(self: Self) -> None:
        proof = {"method": "httpsig", "alg": "ecdsa-p256-sha256", "content-digest-alg": "sha-512"}
        body = self._grant_body(public_jwk(self.key), proof=proof)
        self._assert_invalid_client(self._post_transaction(body, digest_alg="sha-256"))

    def test_transaction_object_form_requires_alg(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key), proof={"method": "httpsig"})
        response = self._post_transaction(body)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_request"

    def test_transaction_signed_with_other_http_signature_library(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))

        class Message:
            method = "POST"
            url = f"{BASE_URL}/transaction"
            headers: dict[str, str] = {"Content-Type": "application/json"}

        message = Message()
        signer = HTTPMessageSigner(
            signature_algorithm=ECDSA_P256_SHA256,
            key_resolver=MappingKeyResolver(public_keys={}, private_keys={"client-key": self.key.get_op_key("sign")}),
        )
        signer.sign(
            message,
            key_id="client-key",
            tag="gnap",
            include_alg=False,
            nonce=uuid.uuid4().hex,
            covered_component_ids=("@method", "@target-uri"),
            body=body,
        )
        response = self.client.post("/transaction", content=body, headers=message.headers)
        assert response.status_code == 200, response.text

    def test_config_flow_key_reference(self: Self) -> None:
        for proof in ["httpsig", {"method": "httpsig", "alg": "ecdsa-p256-sha256"}]:
            with self.subTest(proof=proof):
                self._update_app_config(
                    auth_flows=json.dumps(["TestFlow", "ConfigFlow"]),
                    client_keys=json.dumps(
                        {"ref": {"proof": proof, "jwk": public_jwk(self.key, alg="ES256"), "claims": {"a": "b"}}}
                    ),
                )
                body = self._grant_body("ref")
                response = self._post_transaction(body)
                assert response.status_code == 200, response.text
                claims = self._get_access_token_claims(response.json()["access_token"])
                assert claims["sub"] == "ref"
                assert claims["a"] == "b"

    # key and proof validation

    def test_jwk_without_alg_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key))
        self._assert_invalid_client(self._post_transaction(body))

    def test_jwk_with_unsupported_alg_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES512"))
        self._assert_invalid_client(self._post_transaction(body))

    def test_jwk_without_kid_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256", kid=None))
        self._assert_invalid_client(self._post_transaction(body))

    def test_private_jwk_by_value_rejected(self: Self) -> None:
        private = self.key.export_private(as_dict=True)
        private["alg"] = "ES256"
        body = self._grant_body(private)
        self._assert_invalid_client(self._post_transaction(body))

    def test_symmetric_key_rejected(self: Self) -> None:
        oct_key = jwk.JWK.generate(kty="oct", size=256, kid="client-key")
        data = oct_key.export(as_dict=True)
        data["alg"] = "HS256"
        body = self._grant_body(data)
        self._assert_invalid_client(self._post_transaction(body))

    def test_object_alg_not_matching_key_rejected(self: Self) -> None:
        for proof in [
            {"method": "httpsig", "alg": "ecdsa-p384-sha384"},  # wrong curve
            {"method": "httpsig", "alg": "rsa-pss-sha512"},  # wrong key type
            {"method": "httpsig", "alg": "hmac-sha256"},  # no HMAC
            {"method": "httpsig", "alg": "ed25519"},
        ]:
            with self.subTest(proof=proof):
                body = self._grant_body(public_jwk(self.key), proof=proof)
                self._assert_invalid_client(self._post_transaction(body))

    def test_object_alg_not_matching_key_alg_rejected(self: Self) -> None:
        proof = {"method": "httpsig", "alg": "ecdsa-p256-sha256"}
        body = self._grant_body(public_jwk(self.key, alg="ES384"), proof=proof)
        self._assert_invalid_client(self._post_transaction(body))

    def test_key_alg_not_matching_key_material_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES384"))  # P-256 key claiming ES384
        self._assert_invalid_client(self._post_transaction(body))

    def test_unsupported_content_digest_alg_rejected(self: Self) -> None:
        proof = {"method": "httpsig", "alg": "ecdsa-p256-sha256", "content-digest-alg": "md5"}
        body = self._grant_body(public_jwk(self.key), proof=proof)
        self._assert_invalid_client(self._post_transaction(body))

    # integrity

    def test_tampered_body_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        tampered = body.replace(b"bearer", b"durable")
        self._assert_invalid_client(self._post_transaction(tampered, headers=headers))

    def test_tampered_content_digest_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        headers["Content-Digest"] = content_digest(b"something else")
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_correct_digest_that_is_not_signed_rejected(self: Self) -> None:
        # the body is changed together with its digest, the signature still covers the old digest
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        tampered = body.replace(b"bearer", b"durable")
        headers["Content-Digest"] = content_digest(tampered)
        self._assert_invalid_client(self._post_transaction(tampered, headers=headers))

    def test_wrong_key_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        other_key = generate_key("ES256")  # same kid, other key material
        self._assert_invalid_client(self._post_transaction(body, key=other_key))

    def test_wrong_keyid_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, keyid="other-key"))

    def test_wrong_method_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("PUT", f"{BASE_URL}/transaction", body)
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_wrong_uri_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, sign_url=f"{BASE_URL}/other"))

    def test_missing_or_wrong_tag_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, tag=None))
        self._assert_invalid_client(self._post_transaction(body, tag="other"))
        self._assert_invalid_client(self._post_transaction(body, tag="gnap-rotate"))

    def test_missing_created_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, include_created=False))

    def test_explicit_alg_parameter_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, include_alg=True))

    def test_required_components(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        for components in [
            ["@method", "content-digest"],  # no @target-uri
            ["@target-uri", "content-digest"],  # no @method
            ["@method", "@target-uri"],  # no content-digest
        ]:
            with self.subTest(components=components):
                self._assert_invalid_client(self._post_transaction(body, components=components))

    def test_content_type_not_required_by_default(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        assert self._post_transaction(body, components=["@method", "@target-uri", "content-digest"]).status_code == 200

    def test_content_type_required_by_config(self: Self) -> None:
        self._update_app_config(proof_httpsig_require_content_type="true")
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(
            self._post_transaction(body, components=["@method", "@target-uri", "content-digest"])
        )
        response = self._post_transaction(body, components=["@method", "@target-uri", "content-digest", "content-type"])
        assert response.status_code == 200, response.text

    # freshness

    def test_created_too_old_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        created = int((utc_now() - timedelta(minutes=10)).timestamp())
        self._assert_invalid_client(self._post_transaction(body, created=created))

    def test_created_too_far_in_future_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        created = int((utc_now() + timedelta(minutes=2)).timestamp())
        self._assert_invalid_client(self._post_transaction(body, created=created))

    def test_created_within_clock_skew_accepted(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        created = int((utc_now() + timedelta(seconds=10)).timestamp())
        assert self._post_transaction(body, created=created).status_code == 200

    def test_max_age_config(self: Self) -> None:
        self._update_app_config(proof_httpsig_max_age="PT20M")
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        created = int((utc_now() - timedelta(minutes=10)).timestamp())
        assert self._post_transaction(body, created=created).status_code == 200

    def test_expired_signature_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        expires = int((utc_now() - timedelta(minutes=1)).timestamp())
        self._assert_invalid_client(self._post_transaction(body, expires=expires))

    def test_not_yet_expired_signature_accepted(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        expires = int((utc_now() + timedelta(minutes=1)).timestamp())
        assert self._post_transaction(body, expires=expires).status_code == 200

    # nonce

    def test_nonce_replay_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body, nonce=uuid.uuid4().hex)
        assert self._post_transaction(body, headers=headers).status_code == 200
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_nonce_replay_rejected_without_database(self: Self) -> None:
        # falls back to remembering nonces in the process
        del self.config["mongo_uri"]
        self._update_app_config()
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body, nonce=uuid.uuid4().hex)
        assert self._post_transaction(body, headers=headers).status_code == 200
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_same_nonce_and_kid_for_different_keys_accepted(self: Self) -> None:
        nonce = uuid.uuid4().hex
        for _ in range(2):
            key = generate_key("ES256")  # same kid, different key material
            body = self._grant_body(public_jwk(key, alg="ES256"))
            assert self._post_transaction(body, key=key, nonce=nonce).status_code == 200

    def test_replay_with_same_key_still_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body, nonce=uuid.uuid4().hex)
        assert self._post_transaction(body, headers=headers).status_code == 200
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_other_client_with_same_kid_can_not_burn_nonce(self: Self) -> None:
        nonce = uuid.uuid4().hex
        key_b = generate_key("ES256")  # same kid as self.key
        body_b = self._grant_body(public_jwk(key_b, alg="ES256"))
        assert self._post_transaction(body_b, key=key_b, nonce=nonce).status_code == 200
        body_a = self._grant_body(public_jwk(self.key, alg="ES256"))
        assert self._post_transaction(body_a, nonce=nonce).status_code == 200
        # and the nonce is burnt for each of them
        self._assert_invalid_client(self._post_transaction(body_a, nonce=nonce))
        self._assert_invalid_client(self._post_transaction(body_b, key=key_b, nonce=nonce))

    def _two_signature_headers(
        self: Self, body: bytes, nonces: tuple[str, str], second_valid: bool = True
    ) -> dict[str, str]:
        url = f"{BASE_URL}/transaction"
        base_headers = self._signed_headers("POST", url, body)
        components = ["@method", "@target-uri", "content-digest"]
        signatures = [
            make_signature(
                self.key if valid else generate_key("ES256"),
                "ecdsa-p256-sha256",
                "POST",
                url,
                base_headers,
                components,
                label=label,
                nonce=nonce,
            )
            for label, nonce, valid in [("one", nonces[0], True), ("two", nonces[1], second_valid)]
        ]
        headers = {k: v for k, v in base_headers.items() if k not in ("Signature", "Signature-Input")}
        headers.update(combine(*signatures))
        return headers

    def test_two_valid_signatures_with_different_nonces_accepted_once(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._two_signature_headers(body, (uuid.uuid4().hex, uuid.uuid4().hex))
        assert self._post_transaction(body, headers=headers).status_code == 200
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_replay_with_only_second_nonce_fresh_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        used = uuid.uuid4().hex
        first = self._two_signature_headers(body, (used, uuid.uuid4().hex))
        assert self._post_transaction(body, headers=first).status_code == 200
        # the first nonce is used, the second is fresh
        second = self._two_signature_headers(body, (used, uuid.uuid4().hex))
        self._assert_invalid_client(self._post_transaction(body, headers=second))
        # and the fresh nonce is burnt as well
        third = self._two_signature_headers(body, (uuid.uuid4().hex, uuid.uuid4().hex))
        assert self._post_transaction(body, headers=third).status_code == 200

    def test_invalid_signature_never_consumes_nonce(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        invalid_nonce = uuid.uuid4().hex
        headers = self._two_signature_headers(body, (uuid.uuid4().hex, invalid_nonce), second_valid=False)
        assert self._post_transaction(body, headers=headers).status_code == 200
        self._assert_invalid_client(self._post_transaction(body, headers=headers))
        # the nonce of the invalid signature is still free to use
        assert self._post_transaction(body, nonce=invalid_nonce).status_code == 200

    def test_different_nonces_accepted(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        for _ in range(2):
            assert self._post_transaction(body, nonce=uuid.uuid4().hex).status_code == 200

    def test_unverified_signature_does_not_use_up_nonce(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        nonce = uuid.uuid4().hex
        self._assert_invalid_client(self._post_transaction(body, nonce=nonce, key=generate_key("ES256")))
        assert self._post_transaction(body, nonce=nonce).status_code == 200

    def test_nonce_required_by_default(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        self._assert_invalid_client(self._post_transaction(body, omit_nonce=True))
        assert self._post_transaction(body).status_code == 200

    def test_nonce_not_required_when_disabled(self: Self) -> None:
        self._update_app_config(proof_httpsig_nonce_required="false")
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        assert self._post_transaction(body, omit_nonce=True).status_code == 200
        assert self._post_transaction(body).status_code == 200

    def test_nonce_checked_once_when_flows_fall_through(self: Self) -> None:
        # InteractionFlow verifies the signature and then hands over as there is no interaction request, TestFlow
        # verifies it again. That must not count as a replay.
        self._update_app_config(auth_flows=json.dumps(["InteractionFlow", "TestFlow"]))
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        response = self._post_transaction(body, headers=headers)
        assert response.status_code == 200, response.text
        assert "access_token" in response.json()
        # the same request sent again is a replay
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    # multiple signatures

    def test_first_signature_bad_second_good(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        url = f"{BASE_URL}/transaction"
        base_headers = self._signed_headers("POST", url, body)
        components = ["@method", "@target-uri", "content-digest"]
        for order in [("bad", "good"), ("good", "bad")]:
            signatures = combine(
                *[
                    make_signature(
                        self.key if label == "good" else generate_key("ES256"),
                        "ecdsa-p256-sha256",
                        "POST",
                        url,
                        base_headers,
                        components,
                        label=label,
                    )
                    for label in order
                ]
            )
            headers = {k: v for k, v in base_headers.items() if k not in ("Signature", "Signature-Input")}
            headers.update(signatures)
            assert self._post_transaction(body, headers=headers).status_code == 200

    def test_first_signature_malformed_second_good(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        url = f"{BASE_URL}/transaction"
        base_headers = self._signed_headers("POST", url, body)
        components = ["@method", "@target-uri", "content-digest"]
        wrong_tag = make_signature(
            self.key, "ecdsa-p256-sha256", "POST", url, base_headers, components, label="a", tag="x"
        )
        no_created = make_signature(
            self.key, "ecdsa-p256-sha256", "POST", url, base_headers, components, label="b", include_created=False
        )
        good = make_signature(self.key, "ecdsa-p256-sha256", "POST", url, base_headers, components, label="c")
        headers = {k: v for k, v in base_headers.items() if k not in ("Signature", "Signature-Input")}
        headers.update(combine(wrong_tag, no_created, good))
        assert self._post_transaction(body, headers=headers).status_code == 200

    def test_all_signatures_bad_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        url = f"{BASE_URL}/transaction"
        base_headers = self._signed_headers("POST", url, body)
        components = ["@method", "@target-uri", "content-digest"]
        one = make_signature(
            generate_key("ES256"), "ecdsa-p256-sha256", "POST", url, base_headers, components, label="a"
        )
        two = make_signature(self.key, "ecdsa-p256-sha256", "POST", url, base_headers, components, label="b", tag="x")
        headers = {k: v for k, v in base_headers.items() if k not in ("Signature", "Signature-Input")}
        headers.update(combine(one, two))
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_signature_input_without_signature_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        headers["Signature"] = "other=:AAAA:"
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_malformed_signature_headers_rejected(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", f"{BASE_URL}/transaction", body)
        headers["Signature-Input"] = "not a structured field ("
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    # proxies

    def test_external_base_url(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        external_url = "https://auth.example.com/transaction"
        # by default the uri the server sees is what has to be signed
        self._assert_invalid_client(self._post_transaction(body, sign_url=external_url))
        self._update_app_config(proof_external_base_url="https://auth.example.com/")
        assert self._post_transaction(body, sign_url=external_url).status_code == 200
        # the internal uri is no longer the one to sign
        self._assert_invalid_client(self._post_transaction(body))

    def test_forwarded_headers_are_ignored(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        headers = self._signed_headers("POST", "https://auth.example.com/transaction", body, extra_headers={})
        headers.update({"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.com", "Host": "testserver"})
        self._assert_invalid_client(self._post_transaction(body, headers=headers))

    def test_external_base_url_with_port_and_query(self: Self) -> None:
        self._update_app_config(proof_external_base_url="https://auth.example.com:8443")
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("internal", 8080),
                "path": "/continue/abc",
                "query_string": b"a=1&b=2",
                "headers": [(b"host", b"internal:8080"), (b"x-forwarded-host", b"evil.example.org")],
            }
        )
        assert get_target_uri(request) == "https://auth.example.com:8443/continue/abc?a=1&b=2"
        request = Request(
            {"type": "http", "method": "GET", "scheme": "http", "server": ("internal", 8080), "path": "/x",
             "query_string": b"", "headers": [(b"host", b"internal:8080")]}
        )  # fmt: skip
        assert get_target_uri(request) == "https://auth.example.com:8443/x"
        self._update_app_config(proof_external_base_url="https://auth.example.com:443")
        assert get_target_uri(request) == "https://auth.example.com/x"

    def test_external_base_url_validation(self: Self) -> None:
        for url in [
            "https://auth.example.com/prefix",
            "https://auth.example.com/prefix/",
            "https://user:secret@auth.example.com",
            "https://user@auth.example.com",
            "https://auth.example.com?a=1",
            "https://auth.example.com/?a=1",
            "https://auth.example.com#fragment",
            "ftp://auth.example.com",
        ]:
            with self.subTest(url=url):
                self.config["proof_external_base_url"] = url
                environ.update(self.config)
                test_app.TestAuthServer._clear_lru_cache()
                with self.assertRaises(ConfigurationError):
                    load_config()
        for url in ["https://auth.example.com", "https://auth.example.com/", "http://auth.example.com:8080/"]:
            with self.subTest(url=url):
                self.config["proof_external_base_url"] = url
                environ.update(self.config)
                test_app.TestAuthServer._clear_lru_cache()
                assert load_config().proof_external_base_url is not None

    def test_from_string_in_request_is_not_accepted(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"), proof={"method": "httpsig", "from_string": True})
        response = self._post_transaction(body)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_request"

    def test_jws_uri_uses_external_base_url(self: Self) -> None:
        client_jwk = jwk.JWK.generate(kid="default", kty="EC", crv="P-256")
        grant = {
            "access_token": {"flags": ["bearer"]},
            "client": {"key": {"proof": "jws", "jwk": client_jwk.export_public(as_dict=True)}},
        }

        def post() -> httpx.Response:
            header = {
                "typ": "gnap-binding-jws",
                "alg": "ES256",
                "kid": "default",
                "htm": "POST",
                "uri": "https://auth.example.com/transaction",
                "created": int(utc_now().timestamp()),
            }
            _jws = jws.JWS(payload=json.dumps(grant))
            _jws.add_signature(key=client_jwk, protected=json.dumps(header))
            return self.client.post(
                "/transaction", content=_jws.serialize(compact=True), headers={"Content-Type": "application/jose"}
            )

        self._assert_invalid_client(post())
        self._update_app_config(proof_external_base_url="https://auth.example.com")
        assert post().status_code == 200

    # key bound to the grant

    def test_discovery_lists_httpsig(self: Self) -> None:
        response = self.client.options("/transaction")
        assert response.status_code == 200
        assert "httpsig" in response.json()["key_proofs_supported"]

    def test_missing_signature_headers_fall_through_to_next_flow(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        for headers in [
            {"Content-Type": "application/json"},
            {"Content-Type": "application/json", "Signature": "a=:AA==:"},
        ]:
            response = self.client.post("/transaction", content=body, headers=headers)
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "request_denied"

    def test_only_mtls_flows_reject_httpsig(self: Self) -> None:
        flow = MagicMock()
        key = Key(proof="httpsig", jwk=OKPJWK(kty="OKP", crv="Ed25519", x="AA", kid="k"))
        with self.assertRaises(NextFlowException):
            asyncio.run(OnlyMTLSProofFlow.check_proof(flow, gnap_key=key, gnap_request=None))

    def test_raw_body_available_after_body_was_parsed(self: Self) -> None:
        # the digest is calculated over the raw bytes, so they must be intact after FastAPI parsed the json
        body = b'{ "access_token":{"flags":["bearer"]},\n   "client":{"key":{"proof":"httpsig", "jwk": {"kty":"EC"}}} }'
        seen: list[bytes] = []

        async def fake_check(request: ContextRequest, gnap_key: Key, access_token: str | None = None) -> bool:
            seen.append(await request.body())
            return True

        with mock.patch("auth_server.flows.check_httpsig_proof", side_effect=fake_check):
            response = self.client.post(
                "/transaction",
                content=body,
                headers={"Content-Type": "application/json", "Signature": "a=:AA==:", "Signature-Input": "a=()"},
            )
        assert response.status_code == 200, response.text
        assert seen == [body]

    # continuation and token management

    def _interaction_grant(self: Self, key: jwk.JWK | None = None, alg: str = "ES256") -> dict[str, Any]:
        self._update_app_config(
            auth_flows=json.dumps(["InteractionFlow"]),
            pysaml2_config_path=str(self.datadir / "saml" / "saml2_settings.py"),
            saml2_discovery_service_url="https://disco.example.com/ds/",
        )
        key = key or self.key
        body = self._grant_body(public_jwk(key, alg=alg), interact=True)
        response = self._post_transaction(body, alg=alg, key=key)
        assert response.status_code == 200, response.text
        return response.json()

    def _complete_interaction(self: Self, grant_response: dict[str, Any]) -> None:
        redirect = grant_response["interact"]["redirect"]
        transaction_id = redirect.split(f"{BASE_URL}/interaction/redirect/")[1]
        response = self.client.get(redirect, follow_redirects=False)
        assert response.status_code == 303
        self._fake_saml_authentication(transaction_id=transaction_id)
        response = self._do_consent(transaction_id=transaction_id)
        assert response.status_code == 200

    def _continue_headers(
        self: Self, method: str, uri: str, token: str, body: bytes | None, **kwargs: Any
    ) -> dict[str, str]:
        return self._signed_headers(method, uri, body, extra_headers={"Authorization": f"GNAP {token}"}, **kwargs)

    def test_continue(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]
        self._complete_interaction(grant)

        body = b"{}"
        headers = self._continue_headers("POST", continue_uri, token, body)
        response = self.client.post(continue_uri, content=body, headers=headers)
        assert response.status_code == 200, response.text
        claims = self._get_access_token_claims(response.json()["access_token"])
        assert claims["auth_source"] == "interaction"

    def test_continue_with_other_algorithms(self: Self) -> None:
        for jws_alg in ["ES384", "RS256", "PS512", "EdDSA"]:
            with self.subTest(alg=jws_alg):
                key = generate_key(jws_alg)
                grant = self._interaction_grant(key=key, alg=jws_alg)
                self._complete_interaction(grant)
                continue_uri = grant["continue"]["uri"]
                token = grant["continue"]["access_token"]["value"]
                body = b"{}"
                headers = self._continue_headers("POST", continue_uri, token, body, alg=jws_alg, key=key)
                response = self.client.post(continue_uri, content=body, headers=headers)
                assert response.status_code == 200, response.text

    def test_continue_required_components(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]
        self._complete_interaction(grant)
        body = b"{}"
        for components in [
            ["@method", "content-digest", "authorization"],  # no @target-uri
            ["@method", "@target-uri", "authorization"],  # no content-digest
            ["@method", "@target-uri", "content-digest"],  # no authorization
        ]:
            with self.subTest(components=components):
                headers = self._continue_headers("POST", continue_uri, token, body, components=components)
                response = self.client.post(continue_uri, content=body, headers=headers)
                self._assert_invalid_client(response)
        # the grant is still there for a correct request
        headers = self._continue_headers("POST", continue_uri, token, body)
        assert self.client.post(continue_uri, content=body, headers=headers).status_code == 200

    def test_continue_without_signature_rejected(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]
        self._complete_interaction(grant)
        response = self.client.post(continue_uri, json={}, headers={"Authorization": f"GNAP {token}"})
        assert response.status_code == 400

    def test_continue_signed_by_other_key_rejected(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]
        self._complete_interaction(grant)
        body = b"{}"
        other_key = generate_key("ES256", kid="other-key")
        # a perfectly valid signature, but not from the key bound to the grant
        headers = self._continue_headers("POST", continue_uri, token, body, key=other_key)
        self._assert_invalid_client(self.client.post(continue_uri, content=body, headers=headers))
        # same key id as the grant, different key material
        other_key = generate_key("ES256", kid="client-key")
        headers = self._continue_headers("POST", continue_uri, token, body, key=other_key)
        self._assert_invalid_client(self.client.post(continue_uri, content=body, headers=headers))
        # and the real key still works
        headers = self._continue_headers("POST", continue_uri, token, body)
        assert self.client.post(continue_uri, content=body, headers=headers).status_code == 200

    def test_continue_pending_rotates_token_with_signature(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]
        body = b"{}"
        headers = self._continue_headers("POST", continue_uri, token, body)
        response = self.client.post(continue_uri, content=body, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["continue"]["access_token"]["value"] != token

    def test_delete_continue(self: Self) -> None:
        grant = self._interaction_grant()
        continue_uri = grant["continue"]["uri"]
        token = grant["continue"]["access_token"]["value"]

        # no signature
        response = self.client.delete(continue_uri, headers={"Authorization": f"GNAP {token}"})
        assert response.status_code == 400
        # authorization not covered
        headers = self._continue_headers("DELETE", continue_uri, token, None, components=["@method", "@target-uri"])
        self._assert_invalid_client(self.client.delete(continue_uri, headers=headers))
        # body less request with everything covered
        headers = self._continue_headers("DELETE", continue_uri, token, None)
        response = self.client.delete(continue_uri, headers=headers)
        assert response.status_code == 204, response.text
        # the grant is gone
        headers = self._continue_headers("DELETE", continue_uri, token, None, created=int(utc_now().timestamp()) + 1)
        assert self.client.delete(continue_uri, headers=headers).status_code == 404

    def test_delete_token(self: Self) -> None:
        body = self._grant_body(public_jwk(self.key, alg="ES256"))
        response = self._post_transaction(body)
        assert response.status_code == 200
        manage = response.json()["access_token"]["manage"]
        mgmt_token = manage["access_token"]["value"]

        # signed by another key
        headers = self._continue_headers("DELETE", manage["uri"], mgmt_token, None, key=generate_key("ES256"))
        self._assert_invalid_client(self.client.delete(manage["uri"], headers=headers))
        # authorization not covered
        headers = self._continue_headers(
            "DELETE", manage["uri"], mgmt_token, None, components=["@method", "@target-uri"]
        )
        self._assert_invalid_client(self.client.delete(manage["uri"], headers=headers))
        headers = self._continue_headers("DELETE", manage["uri"], mgmt_token, None)
        response = self.client.delete(manage["uri"], headers=headers)
        assert response.status_code == 204, response.text


class TestProofNonceDB(IsolatedAsyncioTestCase):
    async def asyncSetUp(self: Self) -> None:
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.client = AsyncIOMotorClient(self.mongo_db.uri, tz_aware=True)

    async def asyncTearDown(self: Self) -> None:
        self.mongo_db.conn["auth_server"]["proof_nonces"].drop()
        clear_proof_nonce_cache()
        self.client.close()

    async def test_nonce_store(self: Self) -> None:
        db = await ProofNonceDB.init(db_client=self.client, ttl=timedelta(minutes=6))
        assert await db.check_and_store(key_fingerprint="key", nonce="n1") is True
        assert await db.check_and_store(key_fingerprint="key", nonce="n1") is False
        # nonces are per key
        assert await db.check_and_store(key_fingerprint="other", nonce="n1") is True
        assert await db.check_and_store(key_fingerprint="key", nonce="n2") is True

    async def test_indexes(self: Self) -> None:
        await ProofNonceDB.init(db_client=self.client, ttl=timedelta(minutes=6))
        # a changed ttl replaces the ttl index
        db = await ProofNonceDB.init(db_client=self.client, ttl=timedelta(minutes=7))
        indexes = await db._coll.index_information()
        ttl_indexes = {name: info for name, info in indexes.items() if "expireAfterSeconds" in info}
        assert len(ttl_indexes) == 1
        assert next(iter(ttl_indexes.values()))["expireAfterSeconds"] == 420
        unique = [info for info in indexes.values() if info.get("unique")]
        assert [info["key"] for info in unique] == [[("key_fingerprint", 1), ("nonce", 1)]]

    async def test_check_and_store_all(self: Self) -> None:
        db = await ProofNonceDB.init(db_client=self.client, ttl=timedelta(minutes=6))
        assert await db.check_and_store_all(key_fingerprint="key", nonces=["a", "b"]) is True
        # one used nonce makes the whole call fail, the others are still stored
        assert await db.check_and_store_all(key_fingerprint="key", nonces=["c", "a"]) is False
        assert await db.check_and_store(key_fingerprint="key", nonce="c") is False
        assert await db.check_and_store_all(key_fingerprint="key", nonces=["d", "d"]) is True

    async def test_in_memory_store_all_or_nothing(self: Self) -> None:
        store = InMemoryProofNonceStore(ttl=timedelta(minutes=1))
        assert await store.check_and_store_all(key_fingerprint="key", nonces=["a"]) is True
        assert await store.check_and_store_all(key_fingerprint="key", nonces=["b", "a"]) is False
        assert await store.check_and_store(key_fingerprint="key", nonce="b") is True

    async def test_in_memory_store(self: Self) -> None:
        store = InMemoryProofNonceStore(ttl=timedelta(minutes=1))
        assert await store.check_and_store(key_fingerprint="key", nonce="n1") is True
        assert await store.check_and_store(key_fingerprint="key", nonce="n1") is False
        assert await store.check_and_store(key_fingerprint="other", nonce="n1") is True

        short = InMemoryProofNonceStore(ttl=timedelta(seconds=0))
        assert await short.check_and_store(key_fingerprint="key", nonce="n1") is True
        assert await short.check_and_store(key_fingerprint="key", nonce="n1") is True  # expired right away


class TestProofModels(TestCase):
    def test_proof_string_and_object_form(self: Self) -> None:
        proof = Key(proof="httpsig").proof
        assert proof.method is ProofMethod.HTTPSIG
        assert proof.alg is None
        assert Key(proof="mtls").proof.method is ProofMethod.MTLS
        proof = Key(proof={"method": "httpsig", "alg": "ed25519", "content-digest-alg": "sha-512"}).proof
        assert proof.alg == "ed25519"
        assert proof.content_digest_alg == "sha-512"

    def test_httpsig_object_form_requires_alg(self: Self) -> None:
        with self.assertRaises(ValidationError):
            Key(proof={"method": "httpsig"})
        with self.assertRaises(ValidationError):
            Key(proof={"method": "httpsig", "from_string": True})

    def test_string_form_survives_being_stored(self: Self) -> None:
        # stored transaction state is loaded again from the dumped model
        key = Key(proof="httpsig", jwk={"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "kid": "k", "alg": "ES256"})
        dumped = key.model_dump(exclude_none=True)
        assert dumped["proof"] == "httpsig"
        assert Key(**dumped).proof.alg is None
        object_form = Key(proof={"method": "httpsig", "alg": "ed25519"})
        assert Key(**object_form.model_dump(exclude_none=True)).proof.alg == "ed25519"

    def test_okp_jwk_is_parsed_as_okp(self: Self) -> None:
        key = Key(proof="httpsig", jwk={"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k"})
        assert isinstance(key.jwk, OKPJWK)
        for kty in ["EC", "RSA", "oct"]:
            assert not isinstance(Key(proof="httpsig", jwk={"kty": kty}).jwk, OKPJWK)
