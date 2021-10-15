# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from abc import ABC
from enum import Enum
from typing import Any, Dict, List, Optional, Type, cast, Mapping, TypeVar, Generic

from fastapi import HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK
from pydantic import AnyUrl

from auth_server.config import AuthServerConfig
from auth_server.context import ContextRequest
from auth_server.db.transaction_state import (
    ConfigState,
    MDQState,
    TLSFEDState,
    TestState,
)
from auth_server.mdq import mdq_data_to_key, xml_mdq_get
from auth_server.models.claims import Claims, ConfigClaims, MDQClaims, TLSFEDClaims
from auth_server.models.gnap import (
    AccessTokenFlags,
    AccessTokenResponse,
    Client,
    FinishInteractionMethod,
    GrantResponse,
    InteractionRequest,
    InteractionResponse,
    Key,
    Proof,
    StartInteractionMethod,
    UserCode,
)
from auth_server.proof.common import lookup_client_key_from_config
from auth_server.proof.jws import check_jws_proof, check_jwsd_proof
from auth_server.proof.mtls import check_mtls_proof
from auth_server.tls_fed_auth import entity_to_key, get_entity
from auth_server.utils import get_short_hash, get_values

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class BuiltInFlow(str, Enum):
    CONFIGFLOW = 'ConfigFlow'
    MDQFLOW = 'MDQFlow'
    TESTFLOW = 'TestFlow'
    TLSFEDFLOW = 'TLSFEDFlow'


# Use this to go to next flow
class NextFlowException(HTTPException):
    pass


# Use this to pause the flow and do a user interaction
class InteractionNeededException(HTTPException):
    pass


# Use this to return an error message to the client
class StopTransactionException(HTTPException):
    pass


StateVar = TypeVar('StateVar')


class BaseAuthFlow(Generic[StateVar], ABC):
    def __init__(self, request: ContextRequest, config: AuthServerConfig, signing_key: JWK, state: Mapping[str, Any]):
        self.config = config
        self.request = request
        self.signing_key = signing_key
        self.state = self.load_state(state=state)

    class Meta:
        version: int = 1

    @classmethod
    def get_version(cls) -> int:
        return cls.Meta.version

    @classmethod
    def get_name(cls) -> str:
        return f'{cls.__name__}'

    @staticmethod
    async def steps() -> List[str]:
        # This is the order the methods in the flow will be called
        return [
            'lookup_client',
            'lookup_client_key',
            'validate_proof',
            'handle_access_token',
            'handle_interaction',
            'create_auth_token',
        ]

    @classmethod
    def load_state(cls, state: Mapping[str, Any]):
        raise NotImplementedError()

    async def _create_claims(self) -> Claims:
        return Claims(
            iss=self.config.auth_token_issuer,
            exp=self.config.auth_token_expires_in,
            aud=self.config.auth_token_audience,
            sub=self.request.context.key_reference,
            requested_access=self.state.requested_access,
        )

    async def lookup_client(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def validate_proof(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_subject(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_access_token(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_interaction(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def create_auth_token(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def transaction(self) -> Optional[GrantResponse]:
        for flow_step in await self.steps():
            m = getattr(self, flow_step)
            logger.debug(f'step {flow_step} in {self.get_name()} will be called')
            res = await m()
            if isinstance(res, GrantResponse):
                logger.info(f'step {flow_step} in {self.get_name()} returned GrantResponse')
                logger.debug(res.dict(exclude_unset=True))
                return res
            logger.debug(f'step {flow_step} done, next step will be called')
        return None


FLOW_MAP: Dict[BuiltInFlow, Type[BaseAuthFlow]] = {}  # Register the flow after it is defined below


class CommonFlow(BaseAuthFlow):
    """
    Gather current flow rules and implementation limitations here
    """

    async def lookup_client(self) -> Optional[GrantResponse]:
        if not isinstance(self.state.grant_request.client, Client):
            raise NextFlowException(status_code=400, detail='client by reference not implemented')
        return None

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)

        if not isinstance(self.state.grant_request.client.key, Key):
            raise NextFlowException(status_code=400, detail='key by reference not supported')
        return None

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)
        assert isinstance(self.state.grant_request.client.key, Key)

        # MTLS
        if self.state.grant_request.client.key.proof is Proof.MTLS:
            if not self.state.tls_client_cert:
                raise NextFlowException(status_code=400, detail='no client certificate found')
            self.state.proof_ok = await check_mtls_proof(
                grant_request=self.state.grant_request, cert=self.state.tls_client_cert
            )
        # HTTPSIGN
        elif self.state.grant_request.client.key.proof is Proof.HTTPSIGN:
            raise NextFlowException(status_code=400, detail='httpsign is not implemented')
        # JWS
        elif self.state.grant_request.client.key.proof is Proof.JWS:
            self.state.proof_ok = await check_jws_proof(
                request=self.request, grant_request=self.state.grant_request, jws_header=self.request.context.jws_header
            )
        # JWSD
        elif self.state.grant_request.client.key.proof is Proof.JWSD:
            if not self.state.detached_jws:
                raise NextFlowException(status_code=400, detail='no detached jws header found')
            self.state.proof_ok = await check_jwsd_proof(
                request=self.request, grant_request=self.state.grant_request, detached_jws=self.state.detached_jws
            )
        else:
            raise NextFlowException(status_code=400, detail='no supported proof method')
        return None

    async def handle_access_token(self) -> Optional[GrantResponse]:
        if isinstance(self.state.grant_request.access_token, list):
            if len(self.state.grant_request.access_token) > 1:
                raise NextFlowException(status_code=400, detail='multiple access token requests not supported')
            self.state.grant_request.access_token = self.state.grant_request.access_token[0]
        # TODO: How do we want to validate the access request?
        if self.state.grant_request.access_token.access:
            self.state.requested_access = self.state.grant_request.access_token.access
        return None

    async def handle_interaction(self) -> Optional[GrantResponse]:
        if not isinstance(self.state.grant_request.interact, InteractionRequest):
            return None

        interaction_response = InteractionResponse()
        supported_start_methods = [StartInteractionMethod.REDIRECT, StartInteractionMethod.USER_CODE]
        supported_finish_methods = [FinishInteractionMethod.REDIRECT, FinishInteractionMethod.PUSH]
        start_methods = [
            method for method in self.state.grant_request.interact.start if method in supported_start_methods
        ]
        finish_method = None

        if not start_methods:
            # no start interaction methods shared by client and AS
            detail = (
                f'no supported start interaction method found. AS supports '
                f'{[method.value for method in supported_start_methods]}'
            )
            raise NextFlowException(status_code=400, detail=detail)

        if self.state.grant_request.interact.finish is not None:
            if self.state.grant_request.interact.finish not in supported_finish_methods:
                # no finish interaction methods shared by client and AS
                detail = (
                    f'no supported finish interaction method found. AS supports '
                    f'{[method.value for method in supported_finish_methods]}'
                )
                raise NextFlowException(status_code=400, detail=detail)
            finish_method = self.state.grant_request.interact.finish.method

        # return all mutually supported interaction methods according to draft
        if StartInteractionMethod.REDIRECT in start_methods:
            interaction_response.redirect = cast(
                AnyUrl, self.request.url_for('redirect', transaction_id=get_short_hash())
            )
        if StartInteractionMethod.USER_CODE in start_methods:
            interaction_response.user_code = UserCode(
                code=get_short_hash(length=8), url=cast(AnyUrl, self.request.url_for('user_code_input'))
            )

        # finish method can be one or zero
        if finish_method is not None:
            if finish_method in [FinishInteractionMethod.REDIRECT, FinishInteractionMethod.PUSH]:
                interaction_response.finish = get_short_hash(length=24)

        # TODO: implement continue for interactions with no finish method

        # TODO: save current state
        self.state.grant_response.interact = interaction_response
        return self.state.grant_response

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if not self.state.proof_ok:
            return None

        # Create claims
        claims = await self._create_claims()

        # Create access token
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
        token.make_signed_token(key=self.signing_key)
        auth_response = GrantResponse(
            access_token=AccessTokenResponse(
                flags=[AccessTokenFlags.BEARER], access=self.state.requested_access, value=token.serialize()
            )
        )
        logger.info(f'OK:{self.request.context.key_reference}:{self.config.auth_token_audience}')
        logger.debug(f'claims: {claims}')
        return auth_response


class TestFlow(CommonFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> TestState:
        return TestState.from_dict(state=state)

    async def _create_claims(self) -> Claims:
        claims = await super()._create_claims()
        claims.source = 'test mode'
        return claims

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)
        assert isinstance(self.state.grant_request.client.key, Key)

        if self.state.grant_request.client.key.proof is Proof.TEST:
            logger.warning(f'TEST_MODE - access token will be returned with no proof')
            self.state.proof_ok = True
            return None

        return await super().validate_proof()


FLOW_MAP[BuiltInFlow.TESTFLOW] = TestFlow


class ConfigFlow(CommonFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> ConfigState:
        return ConfigState.from_dict(state=state)

    async def _create_claims(self) -> ConfigClaims:
        base_claims = await super()._create_claims()
        # Update the claims with any claims found in config for this key
        claims_dict = base_claims.dict(exclude_none=True)
        claims_dict.update(self.state.config_claims)
        if 'source' not in claims_dict:
            claims_dict['source'] = 'config'
        return ConfigClaims(**claims_dict)

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)

        if not isinstance(self.state.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        logger.info('Looking up key in config')
        logger.debug(f'key reference: {self.state.grant_request.client.key}')
        client_key = await lookup_client_key_from_config(
            request=self.request, key_id=self.state.grant_request.client.key
        )
        if client_key is None:
            raise NextFlowException(status_code=400, detail='no client key found')

        logger.debug(f'key by reference found: {client_key}')
        self.state.grant_request.client.key = client_key
        # Load any claims associated with the key
        if self.request.context.key_reference in self.config.client_keys:  # please mypy
            self.state.config_claims = self.config.client_keys[self.request.context.key_reference].claims
        return None


FLOW_MAP[BuiltInFlow.CONFIGFLOW] = ConfigFlow


class OnlyMTLSProofFlow(CommonFlow):
    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)
        assert isinstance(self.state.grant_request.client.key, Key)

        if self.state.grant_request.client.key.proof is not Proof.MTLS:
            raise NextFlowException(status_code=400, detail='MTLS is the only supported proof method')
        if not self.state.tls_client_cert:
            raise NextFlowException(status_code=400, detail='no client certificate found')

        self.state.proof_ok = await check_mtls_proof(
            grant_request=self.state.grant_request, cert=self.state.tls_client_cert
        )
        if not self.state.proof_ok:
            raise NextFlowException(status_code=401, detail='no client certificate found')
        return None

    async def handle_interaction(self) -> Optional[GrantResponse]:
        # No interaction for metadata based client authentications
        return None


class MDQFlow(OnlyMTLSProofFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> MDQState:
        return MDQState.from_dict(state=state)

    async def _create_claims(self) -> MDQClaims:
        if not self.state.mdq_data:
            raise NextFlowException(status_code=400, detail='missing mdq data')

        # Get data from metadata
        # entity id
        entity_descriptor = list(
            get_values('urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor', self.state.mdq_data.metadata)
        )
        try:
            entity_id = entity_descriptor[0]['@entityID']
        except (IndexError, KeyError):
            raise NextFlowException(status_code=401, detail='malformed metadata')
        # scopes
        scopes = []
        for scope in get_values('urn:mace:shibboleth:metadata:1.0:Scope', self.state.mdq_data.metadata):
            scopes.append(scope['#text'])
        # source
        registration_info = list(
            get_values('urn:oasis:names:tc:SAML:metadata:rpi:RegistrationInfo', self.state.mdq_data.metadata)
        )
        try:
            source = registration_info[0]['@registrationAuthority']
        except (IndexError, KeyError):
            source = self.config.mdq_server  # Default source to mdq server if registrationAuthority is not set

        base_claims = await super()._create_claims()
        return MDQClaims(**base_claims.dict(exclude_none=True), entity_id=entity_id, scopes=scopes, source=source)

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)

        if not isinstance(self.state.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        key_id = self.state.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if self.config.mdq_server is None:
            logger.error('MDQ server not configured but MDQ flow loaded')
            raise StopTransactionException(status_code=500, detail='bad configuration')

        # Look for a key using mdq
        logger.info(f'Trying to load key from mdq')
        self.state.mdq_data = await xml_mdq_get(entity_id=key_id, mdq_url=self.config.mdq_server)
        client_key = await mdq_data_to_key(self.state.mdq_data)

        if not client_key:
            raise NextFlowException(status_code=400, detail=f'no client key found for {key_id}')
        self.state.grant_request.client.key = client_key
        return None


FLOW_MAP[BuiltInFlow.MDQFLOW] = MDQFlow


class TLSFEDFlow(OnlyMTLSProofFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> TLSFEDState:
        return TLSFEDState.from_dict(state=state)

    async def _create_claims(self) -> TLSFEDClaims:
        if not self.state.entity:
            raise NextFlowException(status_code=400, detail='missing metadata entity')

        # Get scopes from metadata
        scopes = None
        if self.state.entity.extensions and self.state.entity.extensions.saml_scope:
            scopes = self.state.entity.extensions.saml_scope.scope

        base_claims = await super()._create_claims()
        return TLSFEDClaims(
            **base_claims.dict(exclude_none=True),
            entity_id=self.state.entity.entity_id,
            scopes=scopes,
            organization_id=self.state.entity.organization_id,
            source=self.state.entity.issuer,
        )

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)

        if not isinstance(self.state.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        key_id = self.state.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if not self.config.tls_fed_metadata:
            logger.error('TLS fed auth not configured but TLS fed auth flow loaded')
            raise StopTransactionException(status_code=500, detail='bad configuration')

        # Look for a key in the TLS fed metadata
        logger.info(f'Trying to load key from TLS fed auth')
        self.state.entity = await get_entity(entity_id=key_id)
        client_key = await entity_to_key(self.state.entity)

        if not client_key:
            raise NextFlowException(status_code=400, detail=f'no client key found for {key_id}')
        self.state.grant_request.client.key = client_key
        return None

    async def handle_interaction(self) -> Optional[GrantResponse]:
        return None


FLOW_MAP[BuiltInFlow.TLSFEDFLOW] = TLSFEDFlow
