import asyncio
import base64
import importlib
import re
import ssl
import sys
import tempfile
import time
import warnings
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from os import environ
from pathlib import Path
from typing import Any, Self
from unittest import TestCase, mock
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from httpx import Response
from pygamlastan.compat.saml2.mdstore import SourceNotFound
from pygamlastan.compat.saml2.s_utils import UnknownSystemEntity
from pygamlastan.crypto import SamlSigner
from pymongo import MongoClient
from pymongo.errors import AutoReconnect, OperationFailure, ServerSelectionTimeoutError
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import load_config
from auth_server.db.transaction_state import TransactionState
from auth_server.models.gnap import AccessTokenRequest, Client, GrantRequest
from auth_server.routers.saml2_sp import build_discovery_service_url, saml2_router
from auth_server.saml2 import (
    AuthenticationRequestCache,
    AuthnInfo,
    NameID,
    OutstandingQueriesCache,
    ReplayCache,
    SAMLAttributes,
    SessionInfo,
    clear_saml2_sp,
    get_pysaml2_sp_config,
    get_saml2_sp,
    load_sp_config,
    log_safe,
    saml2_module_alias,
)
from auth_server.saml2_mdq import LazyMetadataStore, MDQMetadataSource, run_coroutine_sync
from auth_server.testing import MongoTemporaryInstance
from auth_server.tests.test_app import MockResponse

__author__ = "lundberg"

from auth_server.time_utils import utc_now


class TestLogSafe(TestCase):
    def test_crlf_injection_is_escaped(self: Self) -> None:
        value = "https://idp.example.org\r\n2026-01-01 INFO forged log line\x00\x1b[31m"
        result = log_safe(value)
        assert "\r" not in result
        assert "\n" not in result
        assert "\x00" not in result
        assert "\x1b" not in result
        assert "\\r\\n" in result

    def test_truncated(self: Self) -> None:
        result = log_safe("a" * 1000, max_length=10)
        assert result == "a" * 10 + "..."

    def test_plain_value_unchanged(self: Self) -> None:
        assert log_safe("https://idp.example.org/idp.xml") == "https://idp.example.org/idp.xml"


class TestSAMLSP(TestCase):
    def setUp(self: Self) -> None:
        self.datadir = Path(__file__).with_name("data") / "saml"
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.config: dict[str, Any] = {
            "testing": "true",
            "log_level": "DEBUG",
            "auth_token_issuer": "http://testserver",
            "mongo_uri": self.mongo_db.uri,
            "pysaml2_config_path": f"{self.datadir}/saml2_settings.py",
            "saml2_discovery_service_url": "http://disco.localhost.test/ds/",
        }
        environ.update(self.config)
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)
        self.transaction_states = self.mongo_db.conn["auth_server"]["transaction_states"]
        self.test_transaction_state = TransactionState(
            flow_name="test",
            grant_request=GrantRequest(client=Client(key="test"), access_token=AccessTokenRequest(access=["test"])),
        )
        self.transaction_states.insert_one(self.test_transaction_state.dict(exclude_none=True))
        self.test_idp = "https://idp.example.com/simplesaml/saml2/idp/metadata.php"
        self.test_idp2 = "https://idp2.example.com/simplesaml/saml2/idp/metadata.php"
        self.outstanding_queries_cache = OutstandingQueriesCache(
            db_client=MongoClient(self.mongo_db.uri, tz_aware=True)
        )
        self.authentication_request_cache = AuthenticationRequestCache(
            db_client=MongoClient(self.mongo_db.uri, tz_aware=True)
        )
        self.test_session_info = SessionInfo(
            issuer="https://idp.example.com/simplesaml/saml2/idp/metadata.php",
            authn_info=[
                AuthnInfo(authn_class="https://refeds.org/profile/mfa", authn_authority=[], authn_instant=utc_now())
            ],
            name_id=NameID(
                format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                name_qualifier="",
                sp_name_qualifier="http://test.localhost/saml2-metadata",
                sp_provided_id=None,
                id="1f87035b4c1325b296a53d92097e6b3fa36d7e30ee82e3fcb0680d60243c1f03",
            ),
            attributes=SAMLAttributes(
                assurance=[
                    "http://www.swamid.se/policy/assurance/al1",
                    "http://www.swamid.se/policy/assurance/al2",
                    "https://refeds.org/assurance",
                    "https://refeds.org/assurance/ID/unique",
                    "https://refeds.org/assurance/ID/eppn-unique-no-reassign",
                    "https://refeds.org/assurance/IAP/low",
                    "https://refeds.org/assurance/IAP/medium",
                ],
                common_name="Test Testaren Testsson",
                country_code="se",
                country_name="Sweden",
                date_of_birth="19010203",
                display_name="Testsson",
                eppn="eppn@idp.example.com",
                given_name="Test Testaren",
                home_organization=None,
                home_organization_type=None,
                mail="testsson@example.com",
                nin="190102031234",
                organization_acronym=None,
                organization_name=None,
                personal_identity_number="190102031234",
                scoped_affiliation=None,
                surname="Testsson",
                unique_id="eppn@idp.example.com",
                entitlement=[
                    "urn:mace:swamid.se:example.com:role:member",
                ],
            ),
        )

        self.saml_response_tpl_success = """<?xml version='1.0' encoding='UTF-8'?>
        <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        Destination="{sp_url}saml2-acs" ID="id-88b9f586a2a3a639f9327485cc37c40a" InResponseTo="{session_id}"
        IssueInstant="{timestamp}" Version="2.0">
          <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
          https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
          </samlp:Status>
          <saml:Assertion ID="id-093952102ceb73436e49cb91c58b0578" IssueInstant="{timestamp}" Version="2.0">
            <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
            https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
            <saml:Subject>
              <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier=""
              SPNameQualifier="{sp_url}saml2-metadata">1f87035b4c1325b296a53d92097e6b3fa36d7e30ee82e3fcb0680d60243c1f03</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="{session_id}" NotOnOrAfter="{tomorrow}"
                Recipient="{sp_url}saml2-acs" />
              </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions NotBefore="{yesterday}" NotOnOrAfter="{tomorrow}">
              <saml:AudienceRestriction>
                <saml:Audience>{sp_url}saml2-metadata</saml:Audience>
              </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="{timestamp}" SessionIndex="{session_id}">
              <saml:AuthnContext>
                <saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef>
              </saml:AuthnContext>
            </saml:AuthnStatement>
            <saml:AttributeStatement>
              <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="displayName">
                <saml:AttributeValue xsi:type="xs:string">Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonPrincipalName">
                <saml:AttributeValue xsi:type="xs:string">eppn@idp.example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
              FriendlyName="givenName">
                <saml:AttributeValue xsi:type="xs:string">Test Testaren</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
              FriendlyName="c">
                <saml:AttributeValue xsi:type="xs:string">se</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.43"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="co">
                <saml:AttributeValue xsi:type="xs:string">Sweden</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonUniqueID">
                <saml:AttributeValue xsi:type="xs:string">eppn@idp.example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonAssurance">
                <saml:AttributeValue xsi:type="xs:string">
                http://www.swamid.se/policy/assurance/al1</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">
                http://www.swamid.se/policy/assurance/al2</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/ID/unique</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">
                https://refeds.org/assurance/ID/eppn-unique-no-reassign</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/IAP/low</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/IAP/medium</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
               FriendlyName="cn">
                <saml:AttributeValue xsi:type="xs:string">Test Testaren Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.4"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="sn">
                <saml:AttributeValue xsi:type="xs:string">Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.2428.90.1.5"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="norEduPersonNIN">
                <saml:AttributeValue xsi:type="xs:string">190102031234</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.2.752.29.4.13"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="personalIdentityNumber">
                <saml:AttributeValue xsi:type="xs:string">190102031234</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.3"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="schacDateOfBirth">
                <saml:AttributeValue xsi:type="xs:string">19010203</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail">
                <saml:AttributeValue xsi:type="xs:string">testsson@example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
               NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonTargetedID">
                <saml:AttributeValue>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                   NameQualifier="https://idp.example.com/simplesaml/saml2/idp/metadata.php"
                   SPNameQualifier="http://test.localhost/saml2-metadata">
                   398f4967ef4ec07985d93a9200d3891184b9c0f6c79db53280894ae75673eab8</saml:NameID>
                </saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonEntitlement">
                <saml:AttributeValue xsi:type="xs:string">
                urn:mace:swamid.se:example.com:role:member</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
        </samlp:Response>"""
        self.saml_response_tpl_fail = """<?xml version="1.0" encoding="UTF-8"?>
        <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{sp_url}saml2-acs"
         ID="_ebad01e547857fa54927b020dba1edb1" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
          <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
          https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml2:Issuer>
          <saml2p:Status>
            <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
              <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />
            </saml2p:StatusCode>
            <saml2p:StatusMessage>User login was not successful or could not meet the requirements of the requesting
             application.</saml2p:StatusMessage>
          </saml2p:Status>
        </saml2p:Response>"""

    def _update_app_config(self: Self, config: dict | None = None) -> None:
        if config is not None:
            environ.clear()
            environ.update(config)
        self._clear_lru_cache()
        self.app = init_auth_server_api()
        self.client = TestClient(self.app)

    @staticmethod
    def _clear_lru_cache() -> None:
        # Clear lru_cache to allow config update
        load_config.cache_clear()
        get_pysaml2_sp_config.cache_clear()
        clear_saml2_sp()

    def tearDown(self: Self) -> None:
        self.app = None  # type: ignore
        self.client = None  # type: ignore
        self._clear_lru_cache()
        # Clear saml caches
        self.outstanding_queries_cache._db._drop_whole_collection()
        self.authentication_request_cache._db._drop_whole_collection()
        # Clear environment variables
        environ.clear()

    def _get_transaction_state_by_id(self: Self, transaction_id: str) -> TransactionState:
        doc = self.transaction_states.find_one({"transaction_id": transaction_id})
        assert doc is not None  # please mypy
        assert isinstance(doc, Mapping) is True  # please mypy
        return TransactionState(**doc)

    def _save_transaction_state(self: Self, transaction_state: TransactionState) -> None:
        self.transaction_states.replace_one(
            filter={"transaction_id": transaction_state.transaction_id},
            replacement=transaction_state.dict(exclude_none=True),
        )

    @staticmethod
    def _generate_auth_response(
        request_id: str,
        saml_response_tpl: str,
        assertion_age: timedelta = timedelta(seconds=5),
        assertion_id: str | None = None,
    ) -> bytes:
        """
        Generates a fresh signed authentication response.

        The assertion id is unique for every response, the SAML client refuses to see the same assertion id twice.
        """
        saml_response_tpl = saml_response_tpl.replace(
            "id-093952102ceb73436e49cb91c58b0578", assertion_id or f"id-{uuid4().hex}"
        )

        timestamp = datetime.utcnow() - assertion_age
        tomorrow = datetime.utcnow() + timedelta(days=1)
        yesterday = datetime.utcnow() - timedelta(days=1)

        sp_baseurl = "http://test.localhost/"

        resp = " ".join(
            saml_response_tpl.format(
                session_id=request_id,
                timestamp=timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                tomorrow=tomorrow.strftime("%Y-%m-%dT%H:%M:%SZ"),
                yesterday=yesterday.strftime("%Y-%m-%dT%H:%M:%SZ"),
                sp_url=sp_baseurl,
            ).split()
        )

        return resp.encode("utf-8")

    def _get_current_saml_request_id(self: Self) -> str:
        ids = list(self.outstanding_queries_cache.keys())
        if len(ids) != 1:
            raise RuntimeError("More or less than one authn request in the session")
        return ids[0]

    def test_authn_request(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        response = self.client.get(authn_url, follow_redirects=False)
        assert response.status_code == 303
        assert (
            response.headers["location"].startswith(
                "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="
            )
            is True
        )

    def test_saml_acs(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        transaction_state.requested_subject.authentication_context = ["https://refeds.org/profile/mfa"]
        self._save_transaction_state(transaction_state)
        # do authn request
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        self.client.get(f"{authn_url}", follow_redirects=False)
        auth_req_ref = self._get_current_saml_request_id()
        generated_authn_response = self._generate_auth_response(
            request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success
        )
        # simulate IdP response
        data = {"SAMLResponse": base64.b64encode(generated_authn_response).decode("utf-8"), "RelayState": ""}
        response = self.client.post(
            saml2_router.url_path_for("assertion_consumer_service"), data=data, follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"].startswith("http://testserver/interaction/redirect/") is True

        # check authentication result
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        assert transaction_state.saml_session_info is not None
        assert transaction_state.saml_session_info.issuer == self.test_session_info.issuer
        assert transaction_state.saml_session_info.attributes == self.test_session_info.attributes

    def test_saml_acs_only_targeted_id(self: Self) -> None:
        request_id = self._start_authn()
        tpl = self.saml_response_tpl_success
        for friendly_name in ("eduPersonPrincipalName", "eduPersonUniqueID"):
            tpl, n = re.subn(
                r'<saml:Attribute [^>]*FriendlyName="' + friendly_name + r'">.*?</saml:Attribute>',
                "",
                tpl,
                flags=re.DOTALL,
            )
            assert n == 1
        assert "eduPersonTargetedID" in tpl
        response = self._post_saml_response(self._generate_auth_response(request_id, tpl))
        assert response.status_code == 400
        assert "no supported identity attribute" in response.text
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        assert transaction_state.saml_session_info is None

    def test_saml_acs_status_response(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        transaction_state.requested_subject.authentication_context = ["https://refeds.org/profile/mfa"]
        self._save_transaction_state(transaction_state)
        # do authn request
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        self.client.get(f"{authn_url}", follow_redirects=False)
        auth_req_ref = self._get_current_saml_request_id()
        generated_authn_response = self._generate_auth_response(
            request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_fail
        )
        # simulate IdP response
        data = {"SAMLResponse": base64.b64encode(generated_authn_response).decode("utf-8"), "RelayState": ""}
        response = self.client.post(
            saml2_router.url_path_for("assertion_consumer_service"), data=data, follow_redirects=False
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "SAML Status Error"

    def test_idp_discovery(self: Self) -> None:
        # test initial redirect
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        response = self.client.get(f"{authn_url}", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith(self.config["saml2_discovery_service_url"]) is True
        parsed_redirect_url = urlparse(response.headers["location"])
        parsed_redirect_qs = parse_qs(parsed_redirect_url.query)
        assert parsed_redirect_qs["entityID"][0] == "http://test.localhost/saml2-metadata"
        assert (
            parsed_redirect_qs["return"][0].startswith("http://testserver/saml2/sp/discovery-response/?target=") is True
        )

        # test discovery response
        parsed_return_url = urlparse(parsed_redirect_qs["return"][0])
        parsed_return_qs = parse_qs(parsed_return_url.query)
        discovery_response_url = (
            f"{saml2_router.url_path_for('discovery_service_response')}"
            f"?target={parsed_return_qs['target'][0]}&entityID={self.test_idp}"
        )
        response2 = self.client.get(discovery_response_url, follow_redirects=False)
        assert response2.status_code == 303
        assert (
            response2.headers["location"].startswith(
                "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="
            )
            is True
        )

    def test_get_metadata(self: Self) -> None:
        response = self.client.get(saml2_router.url_path_for("metadata"))
        assert response.headers["content-type"] == "text/xml; charset=utf-8"
        assert response.text is not None

    def _post_saml_response(self: Self, saml_response: bytes) -> Response:
        data = {"SAMLResponse": base64.b64encode(saml_response).decode("utf-8"), "RelayState": ""}
        return self.client.post(
            saml2_router.url_path_for("assertion_consumer_service"), data=data, follow_redirects=False
        )

    def _start_authn_with_discovery(self: Self, idp: str) -> str:
        """Do the authn request and discovery service round trip, return the redirect url to the IdP"""
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        response = self.client.get(authn_url, follow_redirects=False)
        assert response.status_code == 303
        return_qs = parse_qs(urlparse(parse_qs(urlparse(response.headers["location"]).query)["return"][0]).query)
        discovery_response_url = (
            f"{saml2_router.url_path_for('discovery_service_response')}?target={return_qs['target'][0]}&entityID={idp}"
        )
        response = self.client.get(discovery_response_url, follow_redirects=False)
        assert response.status_code == 303
        return response.headers["location"]

    def _start_authn(self: Self) -> str:
        """Do the authn request for the single IdP, return the saml request id"""
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        self.client.get(authn_url, follow_redirects=False)
        return self._get_current_saml_request_id()

    def test_build_discovery_service_url(self: Self) -> None:
        url = build_discovery_service_url("http://disco.test/ds/", "http://sp.test/md", "http://sp.test/ret/?target=1")
        assert url == (
            "http://disco.test/ds/?entityID=http%3A%2F%2Fsp.test%2Fmd&return=http%3A%2F%2Fsp.test%2Fret%2F%3Ftarget%3D1"
        )
        url = build_discovery_service_url("http://disco.test/ds?a=b", "http://sp.test/md", "http://sp.test/ret")
        assert url.startswith("http://disco.test/ds?a=b&entityID=")

    def test_settings_saml2_import_alias(self: Self) -> None:
        # the settings file does `import saml2` and loads unchanged, the alias is only there while it is loaded
        assert get_pysaml2_sp_config("SAML_CONFIG").entityid == "http://test.localhost/saml2-metadata"
        assert "saml2" not in sys.modules

    def test_saml_acs_malformed_response(self: Self) -> None:
        self._start_authn()
        for garbage in [b"this is not xml", b"<samlp:Response", b"\xff\xfe"]:
            response = self._post_saml_response(garbage)
            assert response.status_code == 400
            assert response.json()["detail"] == "Bad SAML response: SAML response is not correctly formatted"

    def test_saml_acs_unsolicited_response(self: Self) -> None:
        self._start_authn()
        generated_authn_response = self._generate_auth_response(
            request_id="id-not-sent-by-us", saml_response_tpl=self.saml_response_tpl_success
        )
        response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: Unsolicited SAML response"
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        assert transaction_state.saml_session_info is None

    def test_replay_cache(self: Self) -> None:
        cache = ReplayCache(db_client=MongoClient(self.mongo_db.uri, tz_aware=True), collection=f"replay_{uuid4().hex}")
        key = uuid4().hex
        assert cache.check_and_insert(key, utc_now() + timedelta(hours=1)) is True
        assert cache.check_and_insert(key, utc_now() + timedelta(hours=1)) is False
        # an expired entry that Mongo has not removed yet is not a replay
        expired = uuid4().hex
        assert cache.check_and_insert(expired, utc_now() - timedelta(seconds=1)) is True
        assert cache.check_and_insert(expired, utc_now() + timedelta(hours=1)) is True
        assert cache.check_and_insert(expired, utc_now() + timedelta(hours=1)) is False
        cache.cleanup()

    def test_saml_acs_replayed_response(self: Self) -> None:
        auth_req_ref = self._start_authn()
        generated_authn_response = self._generate_auth_response(
            request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success
        )
        response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 303
        # the same response again
        response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: Unsolicited SAML response"

    def test_saml_acs_replay_cache_mongo_error_gives_503(self: Self) -> None:
        # a valid response when Mongo fails in the replay cache is a backend outage (503), not a bad response (400).
        # The native client turns the cache exception into a verification error, the real error must survive.
        auth_req_ref = self._start_authn()
        generated_authn_response = self._generate_auth_response(
            request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success
        )
        with mock.patch("pymongo.collection.Collection.insert_one", side_effect=AutoReconnect("replay mongo down")):
            with self.assertLogs("auth_server.saml2", level="ERROR") as logs:
                response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 503
        assert response.json()["detail"] == "SAML backend temporarily unavailable"
        assert any("replay cache backend error" in line for line in logs.output)
        # the error state does not leak into the next request: the same response is accepted when Mongo is back
        response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 303

    def test_saml_acs_replayed_assertion(self: Self) -> None:
        # the same assertion in a response to another (valid) request
        auth_req_ref = self._start_authn()
        assertion_id = f"id-{uuid4().hex}"
        response = self._post_saml_response(
            self._generate_auth_response(
                request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success, assertion_id=assertion_id
            )
        )
        assert response.status_code == 303
        auth_req_ref = self._start_authn()
        response = self._post_saml_response(
            self._generate_auth_response(
                request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success, assertion_id=assertion_id
            )
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: SAML response is not verified"

    def test_outstanding_queries_legacy_value(self: Self) -> None:
        # entries written before the IdP was stored are only the authn request reference
        self.outstanding_queries_cache["id-legacy"] = "authn-ref"
        assert self.outstanding_queries_cache.get("id-legacy") == "authn-ref"
        assert self.outstanding_queries_cache.get_idp("id-legacy") is None
        self.outstanding_queries_cache.set("id-new", "authn-ref-2", idp=self.test_idp)
        assert self.outstanding_queries_cache.get("id-new") == "authn-ref-2"
        assert self.outstanding_queries_cache.get_idp("id-new") == self.test_idp
        assert self.outstanding_queries_cache.get("id-unknown") is None

    def test_saml_acs_legacy_outstanding_query(self: Self) -> None:
        # a request sent before the upgrade, with only one IdP configured the IdP does not need to be known
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        self.authentication_request_cache["authn-ref"] = self.test_transaction_state.transaction_id
        self.outstanding_queries_cache["id-legacy"] = "authn-ref"
        generated_authn_response = self._generate_auth_response(
            request_id="id-legacy", saml_response_tpl=self.saml_response_tpl_success
        )
        response = self._post_saml_response(generated_authn_response)
        assert response.status_code == 303

    def test_two_idps_discovery(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_two_idps.py"
        self._update_app_config(config=self.config)
        for idp, sso_url in [
            (self.test_idp, "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="),
            (self.test_idp2, "https://idp2.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="),
        ]:
            with self.subTest(idp=idp):
                assert self._start_authn_with_discovery(idp).startswith(sso_url)
                self.outstanding_queries_cache._db._drop_whole_collection()

    def test_two_idps_acs(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_two_idps.py"
        self._update_app_config(config=self.config)
        self._start_authn_with_discovery(self.test_idp2)
        auth_req_ref = self._get_current_saml_request_id()
        assert self.outstanding_queries_cache.get_idp(auth_req_ref) == self.test_idp2

        # response from the IdP the request was sent to
        tpl = self.saml_response_tpl_success.replace(self.test_idp, self.test_idp2)
        response = self._post_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=tpl)
        )
        assert response.status_code == 303
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        assert transaction_state.saml_session_info is not None
        assert transaction_state.saml_session_info.issuer == self.test_idp2

    def test_two_idps_acs_response_from_other_idp(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_two_idps.py"
        self._update_app_config(config=self.config)
        self._start_authn_with_discovery(self.test_idp2)
        auth_req_ref = self._get_current_saml_request_id()

        # request was sent to idp2 but idp answers
        response = self._post_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: SAML response is not verified"
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        assert transaction_state.saml_session_info is None

    def test_two_idps_acs_legacy_outstanding_query(self: Self) -> None:
        # with more than one IdP the IdP of an old outstanding query is unknown, the response can not be accepted
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_two_idps.py"
        self._update_app_config(config=self.config)
        self.authentication_request_cache["authn-ref"] = self.test_transaction_state.transaction_id
        self.outstanding_queries_cache["id-legacy"] = "authn-ref"
        response = self._post_saml_response(
            self._generate_auth_response(request_id="id-legacy", saml_response_tpl=self.saml_response_tpl_success)
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: SAML response is not verified"

    def test_mdq_idp(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()

        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            authn_url = saml2_router.url_path_for(
                "authenticate", transaction_id=self.test_transaction_state.transaction_id
            )
            response = self.client.get(authn_url, follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"].startswith(
                "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="
            )
            assert mock_get.await_count == 1
            assert mock_get.await_args is not None
            assert mock_get.await_args.kwargs["url"].startswith("http://mdq.example.com/entities/{sha1}")

            # the response is processed with the IdP metadata from the cache
            auth_req_ref = self._get_current_saml_request_id()
            response = self._post_saml_response(
                self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
            )
            assert response.status_code == 303
            assert mock_get.await_count == 1

    def test_mdq_without_cert_warns(self: Self) -> None:
        with self.assertLogs("auth_server.saml2_mdq", level="WARNING") as logs:
            MDQMetadataSource(url="http://mdq.example.com")
        assert any("has no cert" in line for line in logs.output)

    def test_mdq_with_cert_does_not_warn(self: Self) -> None:
        with self.assertNoLogs("auth_server.saml2_mdq", level="WARNING"):
            self._signed_mdq_source()

    def _set_testing(self: Self, testing: bool) -> None:
        self.config["testing"] = "true" if testing else "false"
        self._update_app_config(config=self.config)

    def test_mdq_http_without_cert_refused_outside_testing(self: Self) -> None:
        self._set_testing(False)
        with self.assertRaises(RuntimeError) as cm:
            MDQMetadataSource(url="http://mdq.example.com")
        assert "http://mdq.example.com" in str(cm.exception)

    def test_mdq_http_without_cert_allowed_in_testing(self: Self) -> None:
        self._set_testing(True)
        MDQMetadataSource(url="http://mdq.example.com")

    def test_mdq_http_with_cert_allowed_outside_testing(self: Self) -> None:
        self._set_testing(False)
        self._signed_mdq_source()

    def test_mdq_https_without_cert_warns_outside_testing(self: Self) -> None:
        self._set_testing(False)
        with self.assertLogs("auth_server.saml2_mdq", level="WARNING") as logs:
            MDQMetadataSource(url="https://mdq.example.com")
        assert any("has no cert" in line for line in logs.output)

    def test_mdq_https_to_http_redirect_refused(self: Self) -> None:
        source = MDQMetadataSource(url="https://mdq.example.com")
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            with open(self.datadir / "remote_metadata.xml", "rb") as f:
                mdq_response = f.read()
            mock_get.return_value = MockResponse(content=mdq_response, url="http://evil.example.com/x")
            with self.assertLogs("auth_server.mdq", level="ERROR") as logs:
                assert run_coroutine_sync(source.prefetch(self.test_idp)) is None
        assert any("downgrade" in line for line in logs.output)

    def test_mdq_redirect_chain_through_http_refused(self: Self) -> None:
        # https -> http -> https: the final URL is https but the request over http was already exposed
        source = MDQMetadataSource(url="https://mdq.example.com")
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            with open(self.datadir / "remote_metadata.xml", "rb") as f:
                mdq_response = f.read()
            hop = MockResponse(url="http://hop.example.com/x", status_code=302)
            mock_get.return_value = MockResponse(
                content=mdq_response, url="https://mdq.example.com/final", history=(hop,)
            )
            with self.assertLogs("auth_server.mdq", level="ERROR") as logs:
                assert run_coroutine_sync(source.prefetch(self.test_idp)) is None
        assert any("downgrade" in line for line in logs.output)

    def test_mdq_https_redirect_to_https_allowed(self: Self) -> None:
        source = MDQMetadataSource(url="https://mdq.example.com")
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            with open(self.datadir / "remote_metadata.xml", "rb") as f:
                mdq_response = f.read()
            mock_get.return_value = MockResponse(content=mdq_response, url="https://other.example.com/x")
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None

    def _mdq_get_kwargs(self: Self, source: MDQMetadataSource) -> dict[str, Any]:
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            with open(self.datadir / "remote_metadata.xml", "rb") as f:
                mock_get.return_value = MockResponse(content=f.read())
            run_coroutine_sync(source.prefetch(self.test_idp))
            assert mock_get.await_args is not None
            return dict(mock_get.await_args.kwargs)

    def _mdq_sp_config(self: Self, *entries: Any) -> Any:  # noqa: ANN401
        path = str(self.datadir / "remote_metadata.xml")
        return load_sp_config(
            {"metadata": {"local": [path], "mdq": list(entries)}, "entityid": "https://sp.example.com/md"}
        )

    def test_mdq_allow_http_without_cert_outside_testing(self: Self) -> None:
        self._set_testing(False)
        with self.assertLogs("auth_server.saml2_mdq", level="WARNING") as logs:
            MDQMetadataSource(url="http://mdq.example.com", allow_http=True)
        assert any("allow_http" in line and "unauthenticated" in line for line in logs.output)

    def test_mdq_http_without_allow_http_still_refused_via_config(self: Self) -> None:
        self._set_testing(False)
        with self.assertRaises(RuntimeError):
            self._mdq_sp_config({"url": "http://mdq.example.com"})
        conf = self._mdq_sp_config({"url": "http://mdq.example.com", "allow_http": True})
        assert len(conf.metadata.mdq_sources) == 1

    def test_mdq_default_does_not_pass_ssl(self: Self) -> None:
        assert "ssl" not in self._mdq_get_kwargs(MDQMetadataSource(url="https://mdq.example.com"))

    def test_mdq_tls_ca_valid(self: Self) -> None:
        ca = str(self.datadir / "certs" / "test_idp_signing.crt")
        source = MDQMetadataSource(url="https://mdq.example.com", tls_ca=ca)
        kwargs = self._mdq_get_kwargs(source)
        assert isinstance(kwargs["ssl"], ssl.SSLContext)
        assert kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED

    def test_mdq_tls_ca_missing(self: Self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            MDQMetadataSource(url="https://mdq.example.com", tls_ca="/does/not/exist.pem")
        assert "tls_ca" in str(cm.exception)

    def test_mdq_tls_ca_not_pem(self: Self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            MDQMetadataSource(url="https://mdq.example.com", tls_ca=str(self.datadir / "remote_metadata.xml"))
        assert "tls_ca" in str(cm.exception)

    def test_mdq_tls_verify_false(self: Self) -> None:
        with self.assertLogs("auth_server.saml2_mdq", level="WARNING") as logs:
            source = MDQMetadataSource(url="https://mdq.example.com", tls_verify=False)
        assert any("tls_verify=false" in line and "trust-on-nothing" in line for line in logs.output)
        assert self._mdq_get_kwargs(source)["ssl"] is False

    def test_mdq_tls_ca_and_tls_verify_false_refused(self: Self) -> None:
        ca = str(self.datadir / "certs" / "test_idp_signing.crt")
        with self.assertRaises(RuntimeError):
            MDQMetadataSource(url="https://mdq.example.com", tls_ca=ca, tls_verify=False)

    def test_mdq_unknown_and_non_bool_settings_refused(self: Self) -> None:
        with self.assertRaises(SourceNotFound) as cm:
            self._mdq_sp_config({"url": "https://mdq.example.com", "tls_verfy": False})
        assert "tls_verfy" in str(cm.exception)
        for key in ("allow_http", "tls_verify"):
            with self.assertRaises(SourceNotFound):
                self._mdq_sp_config({"url": "https://mdq.example.com", key: "false"})

    def test_mdq_ssl_setting_is_per_source(self: Self) -> None:
        conf = self._mdq_sp_config(
            {"url": "https://insecure.example.com", "tls_verify": False}, {"url": "https://normal.example.com"}
        )
        insecure, normal = conf.metadata.mdq_sources
        assert insecure.ssl is False
        assert normal.ssl is None
        assert "ssl" not in self._mdq_get_kwargs(normal)

    def test_mdq_https_downgrade_refused_with_allow_http_and_tls_verify_false(self: Self) -> None:
        source = MDQMetadataSource(url="https://mdq.example.com", allow_http=True, tls_verify=False)
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=b"x", url="http://evil.example.com/x")
            with self.assertLogs("auth_server.mdq", level="ERROR") as logs:
                assert run_coroutine_sync(source.prefetch(self.test_idp)) is None
        assert any("downgrade" in line for line in logs.output)

    def test_discovery_response_sp_only_entity(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self._update_app_config(config=self.config)
        sp_id = "https://sp-only.example.com/sp"
        sp_xml = (
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'validUntil="2099-01-01T00:00:00Z" entityID="{sp_id}"><md:SPSSODescriptor '
            'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            'Location="https://sp-only.example.com/acs" index="0"/>'
            "</md:SPSSODescriptor></md:EntityDescriptor>"
        )
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            idp_xml = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=sp_xml.encode("utf-8"))
            authn_url = saml2_router.url_path_for(
                "authenticate", transaction_id=self.test_transaction_state.transaction_id
            )
            response = self.client.get(authn_url, follow_redirects=False)
            return_qs = parse_qs(urlparse(parse_qs(urlparse(response.headers["location"]).query)["return"][0]).query)
            url = f"{saml2_router.url_path_for('discovery_service_response')}?target={return_qs['target'][0]}"
            response = self.client.get(f"{url}&entityID={sp_id}", follow_redirects=False)
            assert response.status_code == 400
            assert response.json()["detail"] == "requested entity is not an IdP"
            # a normal IdP still works
            mock_get.return_value = MockResponse(content=idp_xml)
            response = self.client.get(f"{url}&entityID={self.test_idp}", follow_redirects=False)
            assert response.status_code == 303

    def test_mdq_idp_not_found(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(status_code=404)
            authn_url = saml2_router.url_path_for(
                "authenticate", transaction_id=self.test_transaction_state.transaction_id
            )
            response = self.client.get(authn_url, follow_redirects=False)
            assert response.status_code == 400
            assert response.json()["detail"] == "requested IdP not found in metadata"

    def test_mdq_metadata_store_lookup(self: Self) -> None:
        # a lookup that was not prefetched (sync code, no running loop) fetches in place
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self._update_app_config(config=self.config)
        store = get_pysaml2_sp_config("SAML_CONFIG").metadata
        assert isinstance(store, LazyMetadataStore)
        assert isinstance(store.mdq_sources[0], MDQMetadataSource)
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            assert self.test_idp in store
            assert store[self.test_idp].entity_id == self.test_idp
            assert mock_get.await_count == 1  # second lookup from the cache
            # an entity that is not what was asked for is not accepted
            assert "https://other.example.com/idp" not in store
            with self.assertRaises(KeyError):
                store["https://other.example.com/idp"]

    def test_both_signature_requirements_off_logs_critical(self: Self) -> None:
        # the default settings file has both want_*_signed False
        self.config["testing"] = "false"
        self._update_app_config(config=self.config)
        with self.assertLogs("auth_server.saml2", level="CRITICAL") as logs:
            get_pysaml2_sp_config("SAML_CONFIG")
        assert any("saml2_settings.py" in line and "disabled" in line for line in logs.output)

    def test_both_signature_requirements_off_no_critical_when_testing(self: Self) -> None:
        self._update_app_config(config=self.config)  # testing is true
        with self.assertNoLogs("auth_server.saml2", level="CRITICAL"):
            get_pysaml2_sp_config("SAML_CONFIG")

    def test_signature_requirements_on_no_critical(self: Self) -> None:
        self.config["testing"] = "false"
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_signed.py"
        self._update_app_config(config=self.config)
        with self.assertNoLogs("auth_server.saml2", level="CRITICAL"):
            get_pysaml2_sp_config("SAML_CONFIG")

    def test_unexpected_value_error_is_500_with_constant_detail(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        with mock.patch(
            "pygamlastan.compat.saml2.client.Saml2Client.parse_authn_request_response",
            side_effect=ValueError("secret internal detail"),
        ):
            response = self._post_saml_response(
                self._generate_auth_response(request_id="id-x", saml_response_tpl=self.saml_response_tpl_success)
            )
        assert response.status_code == 500
        assert response.json()["detail"] == "SAML response processing failed"
        assert "secret" not in response.text

    def test_mdq_miss_in_running_loop_does_not_block(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com")

        async def slow_get(*args: Any, **kwargs: Any) -> MockResponse:  # noqa: ANN401
            await asyncio.sleep(5)
            return MockResponse(content=b"")

        async def lookup() -> float:
            start = time.monotonic()
            with self.assertLogs("auth_server.saml2_mdq", level="ERROR") as logs:
                with self.assertRaises(KeyError):
                    source[self.test_idp]
            assert any(self.test_idp in line and "not prefetched" in line for line in logs.output)
            return time.monotonic() - start

        with mock.patch("aiohttp.ClientSession.get", side_effect=slow_get) as mock_get:
            elapsed = asyncio.run(lookup())
            assert elapsed < 1.0
            assert mock_get.call_count == 0

    def test_mdq_concurrent_prefetch_single_flight(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com")
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()

        async def slow_get(*args: Any, **kwargs: Any) -> MockResponse:  # noqa: ANN401
            await asyncio.sleep(0.1)
            return MockResponse(content=mdq_response)

        async def run() -> list[Any]:
            return list(await asyncio.gather(*[source.prefetch(self.test_idp) for _ in range(5)]))

        with mock.patch("aiohttp.ClientSession.get", side_effect=slow_get) as mock_get:
            results = asyncio.run(run())
            assert mock_get.call_count == 1
            assert all(r is not None and r.entity_id == self.test_idp for r in results)
            assert not source._inflight

    def test_mdq_acs_legacy_outstanding_query_prefetches_issuer_but_refuses(self: Self) -> None:
        # no stored IdP and no single IdP in the settings: the Issuer of the response is prefetched
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self._update_app_config(config=self.config)
        self.authentication_request_cache["authn-ref"] = self.test_transaction_state.transaction_id
        self.outstanding_queries_cache["id-legacy"] = "authn-ref"
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        generated = self._generate_auth_response(
            request_id="id-legacy", saml_response_tpl=self.saml_response_tpl_success
        )
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            response = self._post_saml_response(generated)
            assert mock_get.await_count == 1
        # the Issuer was only prefetched (cache warm). With MDQ the IdP of a legacy entry is not knowable, so the
        # response is still refused: the prefetch widens no trust
        assert response.status_code == 400

    def test_mdq_acs_unsolicited_response_does_not_fetch_metadata(self: Self) -> None:
        # unknown InResponseTo and an Issuer of the attacker's choosing: rejected with no outbound MDQ request
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self._update_app_config(config=self.config)
        generated = self._generate_auth_response(
            request_id="id-never-sent", saml_response_tpl=self.saml_response_tpl_success
        )
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            response = self._post_saml_response(generated)
            assert mock_get.await_count == 0
        assert response.status_code == 400

    def test_mdq_cache_is_bounded(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com", max_entries=3)
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(status_code=404)
            for i in range(10):
                assert run_coroutine_sync(source.prefetch(f"https://idp{i}.example.com")) is None
        assert len(source._cache) == 3
        assert "https://idp9.example.com" in source._cache
        assert "https://idp0.example.com" not in source._cache

    def test_mdq_retry_deadline_capped_at_drop_at(self: Self) -> None:
        # a long negative ttl must not make a stale copy usable past its drop time
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=0.0, negative_ttl=1000.0, max_stale=10.0)
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None
            mock_get.return_value = MockResponse(status_code=500)
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None
        entry = source._cache[self.test_idp]
        assert entry.refresh_at <= entry.drop_at
        # served from the cache before drop_at, refused after it
        with mock.patch("auth_server.saml2_mdq.time.monotonic", return_value=entry.drop_at - 1):
            assert source._cached(self.test_idp) == (True, entry.entity)
        with mock.patch("auth_server.saml2_mdq.time.monotonic", return_value=entry.drop_at + 1):
            assert source._cached(self.test_idp) == (False, None)

    def test_mdq_slow_failed_fetch_does_not_serve_expired_copy(self: Self) -> None:
        # the clock moves past drop_at while the (failing) fetch is in flight
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=0.0, negative_ttl=0.0, max_stale=10.0)
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None
            drop_at = source._cache[self.test_idp].drop_at

            async def slow_failure(*args: Any, **kwargs: Any) -> MockResponse:
                clock.return_value = drop_at + 5  # the request took long enough to outlive the old copy
                return MockResponse(status_code=500)

            mock_get.side_effect = slow_failure
            with mock.patch("auth_server.saml2_mdq.time.monotonic", return_value=drop_at - 5) as clock:
                assert run_coroutine_sync(source.prefetch(self.test_idp)) is None

    def test_mdq_failed_refresh_keeps_last_good(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=0.0, negative_ttl=0.0)
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            good = run_coroutine_sync(source.prefetch(self.test_idp))
            assert good is not None
            for failure in (MockResponse(status_code=500), MockResponse(content=b"<not metadata")):
                mock_get.return_value = failure
                assert run_coroutine_sync(source.prefetch(self.test_idp)) is good
                assert source._cache[self.test_idp].entity is good
            # an entity without a good copy gets a negative entry
            assert run_coroutine_sync(source.prefetch("https://other.example.com/idp")) is None
            assert source._cache["https://other.example.com/idp"].entity is None
            # and a good response replaces the copy again
            mock_get.return_value = MockResponse(content=mdq_response)
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None

    def test_mdq_document_without_valid_until_refused(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com")
        xml = (self.datadir / "remote_metadata.xml").read_text().replace(' validUntil="2099-01-01T00:00:00Z"', "", 1)
        assert "validUntil" not in xml
        with self.assertLogs("auth_server.saml2_mdq", level="ERROR") as logs:
            assert self._mdq_lookup(source, xml) is None
        assert any("no validUntil" in line for line in logs.output)
        assert source._cache[self.test_idp].entity is None  # negative cache

    def test_mdq_stale_copy_bounded_by_grace_and_valid_until(self: Self) -> None:
        now = datetime.now(UTC)
        # far validUntil: usable until refresh time + max_stale, no longer
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=100.0, max_stale=50.0)
        assert self._mdq_lookup(source, self._signed_metadata(valid_until=now + timedelta(days=30))) is not None
        remaining = source._cache[self.test_idp].drop_at - time.monotonic()
        assert remaining > 100.0
        assert remaining <= 150.0
        # near validUntil: never past validUntil
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=100.0, max_stale=50.0)
        assert self._mdq_lookup(source, self._signed_metadata(valid_until=now + timedelta(seconds=120))) is not None
        assert source._cache[self.test_idp].drop_at - time.monotonic() <= 120.0

    def test_mdq_stale_copy_dropped_after_grace(self: Self) -> None:
        source = MDQMetadataSource(url="http://mdq.example.com", ttl=0.0, negative_ttl=0.0, max_stale=0.0)
        xml = (self.datadir / "remote_metadata.xml").read_text()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=xml.encode("utf-8"))
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is not None
            mock_get.return_value = MockResponse(status_code=500)
            assert run_coroutine_sync(source.prefetch(self.test_idp)) is None

    def test_mdq_only_idp_and_queries(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq.py"
        self._update_app_config(config=self.config)
        conf = get_pysaml2_sp_config("SAML_CONFIG")
        assert conf.only_idp() is None
        with open(f"{self.datadir}/remote_metadata.xml", "rb") as f:
            mdq_response = f.read()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=mdq_response)
            assert conf.metadata.name(self.test_idp)
            assert conf.metadata.single_sign_on_service(
                self.test_idp, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            )

    # --- local/remote metadata expiry and refresh ---

    def _expiring_metadata_file(
        self: Self, tmp: str, valid_until: datetime, entities_descriptor: bool = False, name: str = "md.xml"
    ) -> str:
        """
        Write remote_metadata.xml with the given validUntil, on the EntityDescriptor or (entities_descriptor) on an
        enclosing EntitiesDescriptor that the entity inherits it from.
        """
        stamp = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (self.datadir / "remote_metadata.xml").read_text()
        xml = xml.replace(' validUntil="2099-01-01T00:00:00Z"', "", 1).split("?>", 1)[1]
        if entities_descriptor:
            ns = "urn:oasis:names:tc:SAML:2.0:metadata"
            xml = f'<md:EntitiesDescriptor xmlns:md="{ns}" validUntil="{stamp}">{xml}</md:EntitiesDescriptor>'
        else:
            xml = xml.replace("<md:EntityDescriptor ", f'<md:EntityDescriptor validUntil="{stamp}" ', 1)
        path = Path(tmp) / name
        path.write_text(xml)
        return str(path)

    def _local_store(self: Self, path: str) -> LazyMetadataStore:
        conf = load_sp_config({"metadata": {"local": [path]}, "entityid": "https://sp.example.com/md"})
        assert isinstance(conf.metadata, LazyMetadataStore)
        return conf.metadata

    def test_metadata_expired_at_lookup_is_refused(self: Self) -> None:
        now = utc_now()
        for inherited in (False, True):
            with self.subTest(inherited=inherited), tempfile.TemporaryDirectory() as tmp:
                path = self._expiring_metadata_file(tmp, now + timedelta(hours=1), entities_descriptor=inherited)
                store = self._local_store(path)
                assert self.test_idp in store
                assert len(store) == 1
                with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=2)):
                    with self.assertLogs("auth_server.saml2_mdq", level="ERROR") as logs:
                        with self.assertRaises(KeyError):
                            store[self.test_idp]
                        assert store.get(self.test_idp) is None
                        assert self.test_idp not in store
                        assert len(store) == 0
                        assert list(store) == []
                        assert store.with_descriptor("idpsso") == {}
                    assert any(self.test_idp in line and "expired" in line for line in logs.output)
                    with self.assertRaises(UnknownSystemEntity):
                        store.name(self.test_idp)
                    with self.assertRaises(UnknownSystemEntity):
                        store.single_sign_on_service(self.test_idp)

    def test_metadata_expired_when_added_is_refused(self: Self) -> None:
        store = LazyMetadataStore()
        entity = self._local_store(str(self.datadir / "remote_metadata.xml"))[self.test_idp]
        with self.assertLogs("auth_server.saml2_mdq", level="ERROR"):
            store.add_source("src", [entity], deadlines={self.test_idp: utc_now() - timedelta(seconds=1)})
            assert self.test_idp not in store

    def test_metadata_expired_not_found_via_only_idp(self: Self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as tmp:
            path = self._expiring_metadata_file(tmp, now + timedelta(hours=1))
            conf = load_sp_config({"metadata": {"local": [path]}, "entityid": "https://sp.example.com/md"})
            assert conf.only_idp() == self.test_idp
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=2)):
                assert conf.only_idp() is None

    def test_metadata_without_valid_until_never_expires(self: Self) -> None:
        store = self._local_store(str(self.datadir / "remote_metadata.xml"))  # validUntil 2099
        with mock.patch("auth_server.saml2_mdq.utc_now", return_value=utc_now() + timedelta(days=3650)):
            assert self.test_idp in store

    def test_remote_source_refreshed_before_expiry(self: Self) -> None:
        now = utc_now()
        old = self._local_store(str(self.datadir / "remote_metadata.xml"))[self.test_idp]
        new = self._local_store(str(self.datadir / "remote_metadata_idp2.xml"))
        new_id = next(iter(new))
        store = LazyMetadataStore()
        loader = mock.Mock(return_value=([new[new_id]], {new_id: now + timedelta(hours=10)}))
        store.add_source("https://md.example.com/md.xml", [old], {self.test_idp: now + timedelta(hours=2)}, loader)

        async def run(at: datetime) -> None:
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=at):
                await store.refresh_sources()
                task = store._sources["https://md.example.com/md.xml"].task
                if task is not None:
                    await task

        # before the half way point nothing happens
        asyncio.run(run(now + timedelta(minutes=30)))
        loader.assert_not_called()
        # past it the source is reloaded in the background and the new entities are served, the old ones are gone
        asyncio.run(run(now + timedelta(hours=1, minutes=1)))
        loader.assert_called_once()
        with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=1, minutes=2)):
            assert new_id in store
            assert self.test_idp not in store
        # the next refresh point follows the new deadline, so a lookup past the old deadline still works
        with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=3)):
            assert new_id in store

    def test_failed_refresh_keeps_last_good_until_deadline(self: Self) -> None:
        now = utc_now()
        old = self._local_store(str(self.datadir / "remote_metadata.xml"))[self.test_idp]
        store = LazyMetadataStore()
        loader = mock.Mock(side_effect=SourceNotFound("down"))
        store.add_source("src", [old], {self.test_idp: now + timedelta(hours=2)}, loader)

        async def run(at: datetime) -> None:
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=at):
                await store.refresh_sources()
                task = store._sources["src"].task
                if task is not None:
                    await task

        with self.assertLogs("auth_server.saml2_mdq", level="ERROR") as logs:
            asyncio.run(run(now + timedelta(hours=1, minutes=1)))
        assert any("refresh of src failed" in line for line in logs.output)
        assert loader.call_count == 1
        # still served before its own deadline
        with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=1, minutes=30)):
            assert self.test_idp in store
        # a retry is not made before the retry delay
        asyncio.run(run(now + timedelta(hours=1, minutes=1, seconds=10)))
        assert loader.call_count == 1
        # past the deadline the lookups fail closed, also while the (awaited) refresh keeps failing
        with self.assertLogs("auth_server.saml2_mdq", level="ERROR"):
            asyncio.run(run(now + timedelta(hours=2, minutes=1)))
        assert loader.call_count == 2
        with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=2, minutes=1)):
            with self.assertLogs("auth_server.saml2_mdq", level="ERROR"):
                assert self.test_idp not in store

    def test_expired_source_refresh_is_awaited(self: Self) -> None:
        now = utc_now()
        old = self._local_store(str(self.datadir / "remote_metadata.xml"))[self.test_idp]
        store = LazyMetadataStore()
        loader = mock.Mock(return_value=([old], {self.test_idp: now + timedelta(hours=10)}))
        store.add_source("src", [old], {self.test_idp: now + timedelta(hours=1)}, loader)

        async def run() -> bool:
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=2)):
                with self.assertLogs("auth_server.saml2_mdq", level="ERROR"):
                    assert self.test_idp not in store
                await store.refresh_sources()  # no extra await of the task, it was awaited because it was expired
                return self.test_idp in store

        assert asyncio.run(run())

    def test_local_source_reread_on_refresh(self: Self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as tmp:
            path = self._expiring_metadata_file(tmp, now + timedelta(hours=2))
            store = self._local_store(path)
            source = store._sources[path]
            assert source.refresh_at is not None
            assert now + timedelta(minutes=59) < source.refresh_at
            assert source.refresh_at < now + timedelta(hours=1, minutes=1)
            # the file is replaced with a later validUntil
            self._expiring_metadata_file(tmp, now + timedelta(hours=10))

            async def run() -> None:
                with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=1, minutes=5)):
                    await store.refresh_sources()
                    assert source.task is not None
                    await source.task

            asyncio.run(run())
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=3)):
                assert self.test_idp in store

    def test_local_source_not_replaced_stays_expired(self: Self) -> None:
        now = utc_now()
        with tempfile.TemporaryDirectory() as tmp:
            path = self._expiring_metadata_file(tmp, now + timedelta(hours=1))
            store = self._local_store(path)
            at = now + timedelta(hours=2)
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=at):
                with self.assertLogs("auth_server.saml2_mdq", level="ERROR"):
                    assert self.test_idp not in store
                    # the reload reads the same expired file: the compat loader refuses it, nothing is served
                    # (the shim validates against the real clock, so make the file really expired)
                    self._expiring_metadata_file(tmp, now - timedelta(hours=1))
                    asyncio.run(store.refresh_sources())
                assert self.test_idp not in store

    def test_refresh_sources_single_flight(self: Self) -> None:
        now = utc_now()
        old = self._local_store(str(self.datadir / "remote_metadata.xml"))[self.test_idp]
        store = LazyMetadataStore()
        loader = mock.Mock(return_value=([old], {self.test_idp: now + timedelta(hours=10)}))
        store.add_source("src", [old], {self.test_idp: now + timedelta(hours=2)}, loader)

        async def run() -> None:
            with mock.patch("auth_server.saml2_mdq.utc_now", return_value=now + timedelta(hours=1, minutes=5)):
                await asyncio.gather(*(store.refresh_sources() for _ in range(5)))
                task = store._sources["src"].task
                assert task is not None
                await task

        asyncio.run(run())
        assert loader.call_count == 1

    def _signed_metadata(
        self: Self,
        xml_file: str = "remote_metadata.xml",
        key_file: str = "test_idp_signing.key",
        root_id: str | None = "_mdq_root_1",
        uri: str | None = None,
        valid_until: datetime | None = None,
    ) -> str:
        """Sign the EntityDescriptor of a metadata file (enveloped, URI "#<root_id>" unless uri is given)"""
        signer = SamlSigner.from_pem((self.datadir / "certs" / key_file).read_bytes())
        xml = (self.datadir / xml_file).read_text()
        if valid_until is not None:
            # replace the validUntil of the fixture
            xml = re.sub(r' validUntil="[^"]*"', "", xml, count=1)
        attrs = ""
        if root_id is not None:
            attrs += f'ID="{root_id}" '
        if valid_until is not None:
            attrs += f'validUntil="{valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")}" '
        xml = xml.replace("<md:EntityDescriptor ", f"<md:EntityDescriptor {attrs}", 1)
        reference_uri = uri if uri is not None else f"#{root_id}"
        template = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            f'<ds:SignatureMethod Algorithm="{signer.signature_method_uri()}"/>'
            f'<ds:Reference URI="{reference_uri}"><ds:Transforms>'
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/>'
            "</ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"
        )
        pos = xml.index("<md:Extensions>")
        return signer.sign_enveloped(xml[:pos] + template + xml[pos:])

    def _signed_mdq_source(self: Self) -> MDQMetadataSource:
        return MDQMetadataSource(
            url="http://mdq.example.com", cert=str(self.datadir / "certs" / "test_idp_signing.crt")
        )

    def _mdq_lookup(self: Self, source: MDQMetadataSource, xml: str) -> Any:  # noqa: ANN401
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=xml.encode("utf-8"))
            return run_coroutine_sync(source.prefetch(self.test_idp))

    def test_mdq_signed_metadata_accepted(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq_signed.py"
        self._update_app_config(config=self.config)
        store = get_pysaml2_sp_config("SAML_CONFIG").metadata
        assert isinstance(store, LazyMetadataStore)
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=self._signed_metadata().encode("utf-8"))
            assert store[self.test_idp].entity_id == self.test_idp

    def test_mdq_unsigned_metadata_refused(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_mdq_signed.py"
        self._update_app_config(config=self.config)
        store = get_pysaml2_sp_config("SAML_CONFIG").metadata
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(content=(self.datadir / "remote_metadata.xml").read_bytes())
            assert self.test_idp not in store
            with self.assertRaises(KeyError):
                store[self.test_idp]

    def test_mdq_metadata_signed_by_other_key_refused(self: Self) -> None:
        xml = self._signed_metadata(key_file="test_idp_wrong.key")
        assert self._mdq_lookup(self._signed_mdq_source(), xml) is None

    def test_mdq_metadata_tampered_refused(self: Self) -> None:
        xml = self._signed_metadata()
        tampered = xml.replace("example.com</shibmd:Scope>", "evil.example.org</shibmd:Scope>", 1)
        assert tampered != xml
        assert self._mdq_lookup(self._signed_mdq_source(), tampered) is None

    def test_mdq_metadata_signature_wrapping_refused(self: Self) -> None:
        # a validly signed EntityDescriptor (another IdP) next to an unsigned attacker one, in an unsigned parent
        signed_other = self._signed_metadata(xml_file="remote_metadata_idp2.xml").split("?>", 1)[1]
        attacker = (self.datadir / "remote_metadata.xml").read_text().split("?>", 1)[1]
        wrapped = (
            '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">' + signed_other + attacker
        ) + "</md:EntitiesDescriptor>"
        assert self._mdq_lookup(self._signed_mdq_source(), wrapped) is None
        # sanity check, the signed part on its own is fine
        source = self._signed_mdq_source()
        with mock.patch("aiohttp.ClientSession.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MockResponse(
                content=self._signed_metadata(xml_file="remote_metadata_idp2.xml").encode("utf-8")
            )
            assert run_coroutine_sync(source.prefetch("https://idp2.example.com/simplesaml/saml2/idp/metadata.php"))

    def test_mdq_signed_root_without_id_whole_document_reference(self: Self) -> None:
        # No ID on the root, so the only way to sign it is a reference to the whole document (URI=""). That reference
        # covers the root by definition and is accepted.
        xml = self._signed_metadata(root_id=None, uri="")
        assert self._mdq_lookup(self._signed_mdq_source(), xml) is not None
        # also with an ID on the root
        xml = self._signed_metadata(uri="")
        assert self._mdq_lookup(self._signed_mdq_source(), xml) is not None

    def test_mdq_signed_metadata_valid_until(self: Self) -> None:
        now = datetime.now(UTC)
        expired = self._signed_metadata(valid_until=now - timedelta(hours=1))
        assert self._mdq_lookup(self._signed_mdq_source(), expired) is None
        source = self._signed_mdq_source()
        valid = self._signed_metadata(valid_until=now + timedelta(hours=2))
        assert self._mdq_lookup(source, valid) is not None
        # the entry is not trusted longer than validUntil
        assert source._cache[self.test_idp].drop_at - time.monotonic() <= 2 * 3600

    def test_mdq_cert_missing_fails_config_load(self: Self) -> None:
        settings = {"metadata": {"mdq": [{"url": "http://mdq.example.com", "cert": "/nonexistent/mdq.crt"}]}}
        with self.assertRaises(RuntimeError) as cm:
            load_sp_config(settings)
        assert "/nonexistent/mdq.crt" in str(cm.exception)

    def test_mdq_cert_not_pem_fails_config_load(self: Self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "not_a_cert.crt"
            bad.write_text("this is not a certificate")
            settings = {"metadata": {"mdq": [{"url": "http://mdq.example.com", "cert": str(bad)}]}}
            with self.assertRaises(RuntimeError) as cm:
                load_sp_config(settings)
            assert str(bad) in str(cm.exception)

    def test_discovery_response_idp_not_allowed(self: Self) -> None:
        self._update_app_config(config=self.config)
        authn_id = "authn-ref-1"
        self.authentication_request_cache[authn_id] = self.test_transaction_state.transaction_id
        response = self.client.get(
            saml2_router.url_path_for("discovery_service_response"),
            params={"target": authn_id, "entityID": "https://evil.example.com/idp"},
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "requested IdP not allowed"

    def test_saml2_alias_records_use(self: Self) -> None:
        with saml2_module_alias() as used:
            importlib.import_module("saml2.config")

            assert {"saml2", "saml2.config"} <= used
        assert "saml2" not in sys.modules
        with saml2_module_alias() as used:
            pass
        assert used == set()

    def test_saml2_alias_unsupported_module(self: Self) -> None:
        with saml2_module_alias():
            with self.assertRaises(ModuleNotFoundError) as cm:
                importlib.import_module("saml2.entity_category.swamid")
        assert "saml2.entity_category" in str(cm.exception)
        assert "migrated" in str(cm.exception)
        assert "saml2" not in sys.modules

    def test_settings_alias_deprecation_warning(self: Self) -> None:
        self._update_app_config(config=self.config)
        with self.assertLogs("auth_server.saml2", level="WARNING") as logs:
            get_pysaml2_sp_config("SAML_CONFIG")
        assert any("imports pysaml2" in line for line in logs.output)

    def test_settings_no_alias_no_deprecation_warning(self: Self) -> None:
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_compat.py"
        self._update_app_config(config=self.config)
        with self.assertNoLogs("auth_server.saml2", level="WARNING"):
            sp_config = get_pysaml2_sp_config("SAML_CONFIG")
        # neither want_*_signed is set in these settings, they default to the pysaml2 defaults
        assert sp_config.want_response_signed is True
        assert sp_config.want_assertions_signed is True

    def test_settings_unsigned_fixture_disables_signature_checks(self: Self) -> None:
        # guard: the default test settings turn signature checks off, only the signed fixture is secure
        sp_config = get_pysaml2_sp_config("SAML_CONFIG")
        assert sp_config.want_response_signed is False
        assert sp_config.want_assertions_signed is False
        self.config["pysaml2_config_path"] = f"{self.datadir}/saml2_settings_signed.py"
        self._update_app_config(config=self.config)
        sp_config = get_pysaml2_sp_config("SAML_CONFIG")
        assert sp_config.want_response_signed is True
        assert sp_config.want_assertions_signed is True

    def _sign_saml_response(
        self: Self,
        saml_response: bytes,
        sign_response: bool = True,
        sign_assertion: bool = True,
        key_file: str = "test_idp_signing.key",
    ) -> bytes:
        """Sign the Response and/or the Assertion (enveloped, after the Issuer) with a test-only IdP key"""
        signer = SamlSigner.from_pem((self.datadir / "certs" / key_file).read_bytes())

        def template(element_id: str) -> str:
            return (
                '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
                '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                f'<ds:SignatureMethod Algorithm="{signer.signature_method_uri()}"/>'
                f'<ds:Reference URI="#{element_id}"><ds:Transforms>'
                '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
                '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
                '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/>'
                "</ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"
            )

        xml = saml_response.decode("utf-8")
        issuer_end = r"</saml:Issuer>"
        if sign_assertion:
            # the assertion issuer is the second one in the document
            assertion_id = re.search(r'<saml:Assertion ID="([^"]+)"', xml).group(1)  # type: ignore[union-attr]
            idx = xml.index("<saml:Assertion ")
            pos = xml.index(issuer_end, idx) + len(issuer_end)
            xml = signer.sign_enveloped(xml[:pos] + template(assertion_id) + xml[pos:])
        if sign_response:
            response_id = re.search(r'<samlp:Response [^>]*?\bID="([^"]+)"', xml).group(1)  # type: ignore[union-attr]
            pos = xml.index(issuer_end) + len(issuer_end)
            xml = signer.sign_enveloped(xml[:pos] + template(response_id) + xml[pos:])
        return xml.encode("utf-8")

    def _start_authn_signed(self: Self, want_response_signed: bool = True, want_assertions_signed: bool = True) -> str:
        """Use the signature required settings, optionally with other want_*_signed values, and start authn"""
        settings = {"want_response_signed": want_response_signed, "want_assertions_signed": want_assertions_signed}
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        settings_path = Path(tmpdir.name) / "saml2_settings_signed_variant.py"
        settings_path.write_text(
            "import runpy\n"
            f"SAML_CONFIG = runpy.run_path({str(self.datadir / 'saml2_settings_signed.py')!r})['SAML_CONFIG']\n"
            f"SAML_CONFIG['service']['sp'].update({settings!r})\n"
        )
        self.config["pysaml2_config_path"] = str(settings_path)
        return self._start_authn()

    def _post_saml_response_recording_warnings(self: Self, saml_response: bytes) -> tuple[Response, list[str]]:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            response = self._post_saml_response(saml_response)
        return response, [str(w.message) for w in caught]

    PERMISSIVE_WARNING = "SecurityConfig.permissive() disables SAML security checks"

    def test_saml_acs_signed_response_accepted(self: Self) -> None:
        auth_req_ref = self._start_authn_signed()
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
        )
        response, caught = self._post_saml_response_recording_warnings(signed)
        assert response.status_code == 303
        # the signature verified path is not the permissive one
        assert not any(self.PERMISSIVE_WARNING in w for w in caught)

    def test_saml_acs_unsigned_response_uses_permissive_when_signatures_disabled(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        auth_req_ref = self._get_current_saml_request_id_after_authn()
        response, caught = self._post_saml_response_recording_warnings(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
        )
        assert response.status_code == 303
        assert any(self.PERMISSIVE_WARNING in w for w in caught)

    def _get_current_saml_request_id_after_authn(self: Self) -> str:
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        self.client.get(authn_url, follow_redirects=False)
        return self._get_current_saml_request_id()

    def test_saml_acs_unsigned_response_rejected(self: Self) -> None:
        auth_req_ref = self._start_authn_signed()
        response, caught = self._post_saml_response_recording_warnings(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
        )
        assert response.status_code == 400
        assert "SAML response signature is invalid" in response.json()["detail"]
        assert not any(self.PERMISSIVE_WARNING in w for w in caught)

    def test_saml_acs_wrong_key_rejected(self: Self) -> None:
        auth_req_ref = self._start_authn_signed()
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success),
            key_file="test_idp_wrong.key",
        )
        response = self._post_saml_response(signed)
        assert response.status_code == 400
        assert "SAML response signature is invalid" in response.json()["detail"]

    def test_saml_acs_tampered_signed_response_rejected(self: Self) -> None:
        auth_req_ref = self._start_authn_signed()
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success)
        )
        tampered = signed.replace(b"eppn@idp.example.com", b"evil@idp.example.com", 1)
        assert tampered != signed
        response = self._post_saml_response(tampered)
        assert response.status_code == 400
        assert "SAML response signature is invalid" in response.json()["detail"]

    def test_saml_acs_signed_assertion_only(self: Self) -> None:
        # default settings require both signatures, an assertion only signed response is refused
        auth_req_ref = self._start_authn_signed()
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success),
            sign_response=False,
        )
        response = self._post_saml_response(signed)
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: SAML response is not verified"
        # accepted when only the assertion has to be signed
        self.outstanding_queries_cache._db._drop_whole_collection()
        auth_req_ref = self._start_authn_signed(want_response_signed=False, want_assertions_signed=True)
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success),
            sign_response=False,
        )
        assert self._post_saml_response(signed).status_code == 303

    def test_saml_acs_signed_response_only(self: Self) -> None:
        auth_req_ref = self._start_authn_signed()
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success),
            sign_assertion=False,
        )
        response = self._post_saml_response(signed)
        assert response.status_code == 400
        assert response.json()["detail"] == "Bad SAML response: SAML response is not verified"
        # accepted when only the response has to be signed
        self.outstanding_queries_cache._db._drop_whole_collection()
        auth_req_ref = self._start_authn_signed(want_response_signed=True, want_assertions_signed=False)
        signed = self._sign_saml_response(
            self._generate_auth_response(request_id=auth_req_ref, saml_response_tpl=self.saml_response_tpl_success),
            sign_assertion=False,
        )
        assert self._post_saml_response(signed).status_code == 303

    def test_saml_response_without_in_response_to(self: Self) -> None:
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        response = self._post_saml_response(
            self._generate_auth_response(request_id="id-nothing", saml_response_tpl=self.saml_response_tpl_success)
        )
        assert response.status_code == 400

    def test_get_saml2_sp_is_built_once(self: Self) -> None:
        with mock.patch("auth_server.saml2.ReplayCache", wraps=ReplayCache) as replay_cache:
            first, second, third = asyncio.run(self._get_sps(3))
            assert first is not None
            assert first is second is third
            assert replay_cache.call_count == 1

    @staticmethod
    async def _get_sps(count: int) -> list[Any]:
        # concurrent first calls build one SP
        return list(await asyncio.gather(*[get_saml2_sp() for _ in range(count)]))

    def test_get_saml2_sp_rebuilt_after_config_change(self: Self) -> None:
        first = asyncio.run(get_saml2_sp())
        self._update_app_config()
        second = asyncio.run(get_saml2_sp())
        assert first is not None
        assert second is not None
        assert first is not second

    def test_get_saml2_sp_build_failure_not_cached(self: Self) -> None:
        with mock.patch("auth_server.saml2.ReplayCache", side_effect=ServerSelectionTimeoutError("no mongo")):
            with self.assertRaises(ServerSelectionTimeoutError):
                asyncio.run(get_saml2_sp())
        assert asyncio.run(get_saml2_sp()) is not None

    def test_mongo_timeouts_set(self: Self) -> None:
        sp = asyncio.run(get_saml2_sp())
        assert sp is not None
        client = sp.outstanding_queries_cache._db._conn
        assert client.options.server_selection_timeout == 2
        assert client.options.pool_options.connect_timeout == 2
        assert client.options.pool_options.socket_timeout == 3

    def test_mongo_unavailable_gives_503(self: Self) -> None:
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        with mock.patch(
            "auth_server.db.mongo_cache.MongoCache.__setitem__", side_effect=ServerSelectionTimeoutError("no mongo")
        ):
            response = self.client.get(authn_url, follow_redirects=False)
        assert response.status_code == 503
        assert response.json()["detail"] == "SAML backend temporarily unavailable"

    def test_mongo_unavailable_on_build_gives_503(self: Self) -> None:
        with mock.patch("auth_server.saml2.ReplayCache", side_effect=AutoReconnect("connection lost")):
            response = self.client.get(saml2_router.url_path_for("metadata"))
        assert response.status_code == 503
        assert response.json()["detail"] == "SAML backend temporarily unavailable"
        # recovers when Mongo is back
        assert self.client.get(saml2_router.url_path_for("metadata")).status_code == 200

    def test_mdq_bare_string(self: Self) -> None:
        settings = {"metadata": {"mdq": ["https://mdq.example.com/"]}, "entityid": "https://sp.example.com/md"}
        with self.assertLogs("auth_server.saml2", level="INFO") as logs:
            conf = load_sp_config(settings)
        assert any("bare url" in line for line in logs.output)
        assert isinstance(conf.metadata, LazyMetadataStore)
        assert str(conf.metadata.mdq_sources[0].url).startswith("https://mdq.example.com")
        # the dict form still works
        conf = load_sp_config({"metadata": {"mdq": [{"url": "https://mdq.example.com/"}]}, "entityid": "x"})
        assert isinstance(conf.metadata, LazyMetadataStore)
        assert len(conf.metadata.mdq_sources) == 1

    def test_mdq_entry_without_url(self: Self) -> None:
        for entry in [{"cert": "x"}, {"url": ""}, 5]:
            with self.subTest(entry=entry):
                with self.assertRaises(SourceNotFound):
                    load_sp_config({"metadata": {"mdq": [entry]}, "entityid": "x"})

    def test_startup_validates_saml_config(self: Self) -> None:
        with TestClient(self.app):
            assert asyncio.run(get_saml2_sp()) is not None

    def test_startup_tolerates_mongo_unavailable(self: Self) -> None:
        # connectivity problems only log a warning, the SP is built on first use
        with mock.patch("auth_server.api.get_saml2_sp", side_effect=ServerSelectionTimeoutError("no mongo")):
            with TestClient(self.app):
                pass

    def test_startup_fails_on_persistent_mongo_error(self: Self) -> None:
        # not an outage: auth failure, index conflict, bad options. Must fail the startup.
        with mock.patch("auth_server.api.get_saml2_sp", side_effect=OperationFailure("index conflict")):
            with self.assertRaises(OperationFailure):
                with TestClient(self.app):
                    pass

    def test_startup_fails_on_bad_saml_config(self: Self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad_settings.py"
            bad.write_text("SAML_CONFIG = {'metadata': {'mdq': [{'cert': 'no url'}]}, 'entityid': 'x'}\n")
            self.config["pysaml2_config_path"] = str(bad)
            self._update_app_config(config=self.config)
            with self.assertRaises(SourceNotFound):
                with TestClient(self.app):
                    pass
