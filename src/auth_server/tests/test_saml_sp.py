# -*- coding: utf-8 -*-
import base64
from datetime import datetime, timedelta
from os import environ
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from unittest import TestCase
from urllib.parse import parse_qs, urlparse

from pymongo import MongoClient
from starlette.testclient import TestClient

from auth_server.api import init_auth_server_api
from auth_server.config import load_config
from auth_server.db.transaction_state import TransactionState
from auth_server.models.gnap import AccessTokenRequest, Client, GrantRequest
from auth_server.routers.saml2_sp import saml2_router
from auth_server.saml2 import (
    AuthenticationRequestCache,
    AuthnInfo,
    NameID,
    OutstandingQueriesCache,
    SAMLAttributes,
    SessionInfo,
    get_pysaml2_sp_config,
)
from auth_server.testing import MongoTemporaryInstance

__author__ = "lundberg"

from auth_server.time_utils import utc_now


class TestSAMLSP(TestCase):
    def setUp(self) -> None:
        self.datadir = Path(__file__).with_name("data") / "saml"
        self.mongo_db = MongoTemporaryInstance.get_instance()
        self.config: Dict[str, Any] = {
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
                targeted_id="https://idp.example.com/simplesaml/saml2/idp/metadata.php!http://test.localhost/saml2-metadata!398f4967ef4ec07985d93a9200d3891184b9c0f6c79db53280894ae75673eab8",
                unique_id="eppn@idp.example.com",
                entitlement=[
                    "urn:mace:swamid.se:example.com:role:member",
                ],
            ),
        )

        self.saml_response_tpl_success = """<?xml version='1.0' encoding='UTF-8'?>
        <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="{sp_url}saml2-acs" ID="id-88b9f586a2a3a639f9327485cc37c40a" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
          <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
          </samlp:Status>
          <saml:Assertion ID="id-093952102ceb73436e49cb91c58b0578" IssueInstant="{timestamp}" Version="2.0">
            <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml:Issuer>
            <saml:Subject>
              <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="" SPNameQualifier="{sp_url}saml2-metadata">1f87035b4c1325b296a53d92097e6b3fa36d7e30ee82e3fcb0680d60243c1f03</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="{session_id}" NotOnOrAfter="{tomorrow}" Recipient="{sp_url}saml2-acs" />
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
              <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="displayName">
                <saml:AttributeValue xsi:type="xs:string">Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonPrincipalName">
                <saml:AttributeValue xsi:type="xs:string">eppn@idp.example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="givenName">
                <saml:AttributeValue xsi:type="xs:string">Test Testaren</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="c">
                <saml:AttributeValue xsi:type="xs:string">se</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.43" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="co">
                <saml:AttributeValue xsi:type="xs:string">Sweden</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonUniqueID">
                <saml:AttributeValue xsi:type="xs:string">eppn@idp.example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonAssurance">
                <saml:AttributeValue xsi:type="xs:string">http://www.swamid.se/policy/assurance/al1</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">http://www.swamid.se/policy/assurance/al2</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/ID/unique</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/ID/eppn-unique-no-reassign</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/IAP/low</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://refeds.org/assurance/IAP/medium</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="cn">
                <saml:AttributeValue xsi:type="xs:string">Test Testaren Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="sn">
                <saml:AttributeValue xsi:type="xs:string">Testsson</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.2428.90.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="norEduPersonNIN">
                <saml:AttributeValue xsi:type="xs:string">190102031234</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.2.752.29.4.13" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="personalIdentityNumber">
                <saml:AttributeValue xsi:type="xs:string">190102031234</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="schacDateOfBirth">
                <saml:AttributeValue xsi:type="xs:string">19010203</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail">
                <saml:AttributeValue xsi:type="xs:string">testsson@example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonTargetedID">
                <saml:AttributeValue>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://idp.example.com/simplesaml/saml2/idp/metadata.php" SPNameQualifier="http://test.localhost/saml2-metadata">398f4967ef4ec07985d93a9200d3891184b9c0f6c79db53280894ae75673eab8</saml:NameID>
                </saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="eduPersonEntitlement">
                <saml:AttributeValue xsi:type="xs:string">urn:mace:swamid.se:example.com:role:member</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
        </samlp:Response>"""
        self.saml_response_tpl_fail = """<?xml version="1.0" encoding="UTF-8"?>
        <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{sp_url}saml2-acs" ID="_ebad01e547857fa54927b020dba1edb1" InResponseTo="{session_id}" IssueInstant="{timestamp}" Version="2.0">
          <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/simplesaml/saml2/idp/metadata.php</saml2:Issuer>
          <saml2p:Status>
            <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
              <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />
            </saml2p:StatusCode>
            <saml2p:StatusMessage>User login was not successful or could not meet the requirements of the requesting application.</saml2p:StatusMessage>
          </saml2p:Status>
        </saml2p:Response>"""

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
        get_pysaml2_sp_config.cache_clear()

    def tearDown(self) -> None:
        self.app = None  # type: ignore
        self.client = None  # type: ignore
        self._clear_lru_cache()
        # Clear saml caches
        self.outstanding_queries_cache._db._drop_whole_collection()
        self.authentication_request_cache._db._drop_whole_collection()
        # Clear environment variables
        environ.clear()

    def _get_transaction_state_by_id(self, transaction_id) -> TransactionState:
        doc = self.transaction_states.find_one({"transaction_id": transaction_id})
        assert doc is not None  # please mypy
        assert isinstance(doc, Mapping) is True  # please mypy
        return TransactionState(**doc)

    def _save_transaction_state(self, transaction_state: TransactionState) -> None:
        self.transaction_states.replace_one(
            filter={"transaction_id": transaction_state.transaction_id},
            replacement=transaction_state.dict(exclude_none=True),
        )

    @staticmethod
    def _generate_auth_response(
        request_id: str, saml_response_tpl: str, assertion_age: timedelta = timedelta(seconds=5)
    ) -> bytes:
        """
        Generates a fresh signed authentication response
        """

        timestamp = datetime.utcnow() - assertion_age
        tomorrow = datetime.utcnow() + timedelta(days=1)
        yesterday = datetime.utcnow() - timedelta(days=1)

        sp_baseurl = "http://test.localhost/"

        resp = " ".join(
            saml_response_tpl.format(
                **{
                    "session_id": request_id,
                    "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "tomorrow": tomorrow.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "yesterday": yesterday.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sp_url": sp_baseurl,
                }
            ).split()
        )

        return resp.encode("utf-8")

    def _get_current_saml_request_id(self) -> str:
        ids = list(self.outstanding_queries_cache.keys())
        if len(ids) != 1:
            raise RuntimeError("More or less than one authn request in the session")
        return ids[0]

    def test_authn_request(self):
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        response = self.client.get(authn_url, allow_redirects=False)
        assert response.status_code == 303
        assert (
            response.headers["location"].startswith(
                "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="
            )
            is True
        )

    def test_saml_acs(self):
        self.config["saml2_single_idp"] = self.test_idp
        self._update_app_config(config=self.config)
        transaction_state = self._get_transaction_state_by_id(self.test_transaction_state.transaction_id)
        transaction_state.requested_subject.authentication_context = ["https://refeds.org/profile/mfa"]
        self._save_transaction_state(transaction_state)
        # do authn request
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        self.client.get(f"{authn_url}", allow_redirects=False)
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
        assert transaction_state.saml_assertion is not None
        assert transaction_state.saml_assertion.issuer == self.test_session_info.issuer
        assert transaction_state.saml_assertion.attributes == self.test_session_info.attributes

    def test_idp_discovery(self):
        # test initial redirect
        authn_url = saml2_router.url_path_for("authenticate", transaction_id=self.test_transaction_state.transaction_id)
        response = self.client.get(f"{authn_url}", allow_redirects=False)
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
            f'{saml2_router.url_path_for("discovery_service_response")}'
            f'?target={parsed_return_qs["target"][0]}&entityID={self.test_idp}'
        )
        response2 = self.client.get(discovery_response_url, allow_redirects=False)
        assert response2.status_code == 303
        assert (
            response2.headers["location"].startswith(
                "https://idp.example.com/simplesaml/saml2/idp/SSOService.php?SAMLRequest="
            )
            is True
        )

    def test_get_metadata(self):
        response = self.client.get(saml2_router.url_path_for("metadata"))
        assert response.headers["content-type"] == "text/xml; charset=utf-8"
        assert response.text is not None
