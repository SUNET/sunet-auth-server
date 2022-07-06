# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from abc import ABC
from typing import Any, List, Mapping, Optional, Union, cast

from fastapi import HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK
from pydantic import AnyUrl

from auth_server.config import AuthServerConfig
from auth_server.context import ContextRequest
from auth_server.db.transaction_state import ConfigState, MDQState, TestState, TLSFEDState, get_transaction_state_db
from auth_server.mdq import mdq_data_to_key, xml_mdq_get
from auth_server.models.claims import Claims, ConfigClaims, MDQClaims, TLSFEDClaims
from auth_server.models.gnap import (
    AccessTokenFlags,
    AccessTokenResponse,
    Client,
    Continue,
    ContinueAccessToken,
    ContinueRequest,
    FinishInteractionMethod,
    GrantRequest,
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
from auth_server.utils import get_hex_uuid4, get_values

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


# Use this to go to next flow
class NextFlowException(HTTPException):
    pass


# Use this to pause the flow and do a user interaction
class InteractionNeededException(HTTPException):
    pass


# Use this to return an error message to the client
class StopTransactionException(HTTPException):
    pass


class BaseAuthFlow(ABC):
    def __init__(
        self,
        request: ContextRequest,
        config: AuthServerConfig,
        signing_key: JWK,
        state: Mapping[str, Any],
    ):
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

    async def check_proof(self, gnap_key: Key, gnap_request: Optional[Union[GrantRequest, ContinueRequest]]) -> bool:
        # MTLS
        if gnap_key.proof is Proof.MTLS:
            if not self.state.tls_client_cert:
                raise NextFlowException(status_code=400, detail='no client certificate found')
            return await check_mtls_proof(gnap_key=gnap_key, cert=self.state.tls_client_cert)
        # HTTPSIGN
        elif gnap_key.proof is Proof.HTTPSIGN:
            raise NextFlowException(status_code=400, detail='httpsign is not implemented')
        # JWS
        elif gnap_request and gnap_key.proof is Proof.JWS:
            return await check_jws_proof(
                request=self.request, gnap_key=gnap_key, gnap_request=gnap_request, jws_header=self.state.jws_header
            )
        # JWSD
        elif gnap_request and gnap_key.proof is Proof.JWSD:
            if not self.state.detached_jws:
                raise NextFlowException(status_code=400, detail='no detached jws header found')
            return await check_jwsd_proof(
                request=self.request,
                gnap_key=gnap_key,
                gnap_request=gnap_request,
                detached_jws=self.state.detached_jws,
                key_reference=self.state.key_reference,
            )
        else:
            raise NextFlowException(status_code=400, detail='no supported proof method')

    async def create_claims(self) -> Claims:
        return Claims(
            iss=self.config.auth_token_issuer,
            exp=self.config.auth_token_expires_in,
            aud=self.config.auth_token_audience,
            sub=self.state.key_reference,
            requested_access=self.state.requested_access,
        )

    async def lookup_client(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, should be enforced in previous steps
        assert isinstance(self.state.grant_request.client, Client)
        assert isinstance(self.state.grant_request.client.key, Key)

        self.state.proof_ok = await self.check_proof(
            gnap_key=self.state.grant_request.client.key,
            gnap_request=self.state.grant_request,
        )
        return None

    async def handle_subject(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_access_token(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_interaction(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def create_auth_token(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def _run_steps(self, steps: List[str]) -> Optional[GrantResponse]:
        for flow_step in steps:
            m = getattr(self, flow_step)
            self.state.flow_step = flow_step
            logger.debug(f'step {flow_step} in {self.get_name()} will be called')
            res = await m()
            if isinstance(res, GrantResponse):
                logger.info(f'step {flow_step} in {self.get_name()} returned GrantResponse')
                logger.debug(res.dict(exclude_none=True))
                return res
            logger.debug(f'step {flow_step} done, next step will be called')
        return None

    async def continue_transaction(self, continue_request: ContinueRequest):
        # check the client authentication for the continuation request against the same key used for the grant request
        self.state.proof_ok = self.check_proof(
            gnap_key=self.state.grant_request.client.key, gnap_request=continue_request
        )

        # run the remaining steps in the flow
        steps = await self.steps()
        continue_steps_index = steps.index(self.state.flow_step)
        continue_steps = steps[continue_steps_index + 1 :]  # remaining steps starts at latest completed step + 1
        return await self._run_steps(steps=continue_steps)

    async def transaction(self) -> Optional[GrantResponse]:
        steps = await self.steps()
        return await self._run_steps(steps=steps)


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

        transaction_state_db = await get_transaction_state_db()
        if transaction_state_db is None:
            raise NextFlowException(status_code=400, detail='interact not supported')

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
            if self.state.grant_request.interact.finish.method not in supported_finish_methods:
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
                AnyUrl, self.request.url_for('redirect', transaction_id=self.state.transaction_id)
            )
        if StartInteractionMethod.USER_CODE in start_methods:
            self.state.user_code = get_hex_uuid4(length=8)
            interaction_response.user_code = UserCode(
                code=self.state.user_code, url=cast(AnyUrl, self.request.url_for('user_code_input'))
            )

        # finish method can be one or zero
        if finish_method is not None:
            # nonce used to verify finish method redirect and push call
            interaction_response.finish = get_hex_uuid4(length=24)
            # use continue url with no continue id id as the client will get the interaction reference
            # in the interaction finish
            self.state.interaction_reference = get_hex_uuid4(length=24)
            continue_url = self.request.url_for('continue_transaction')
            wait = None  # the client will be notified when the interaction is complete
        else:
            # as the client doesn't support interaction finish we have to use the continue reference in the
            # continue uri
            self.state.continue_reference = get_hex_uuid4(length=8)
            continue_url = self.request.url_for(
                'continue_transaction', continue_reference=self.state.continue_reference
            )
            wait = 30  # I guess it takes at least 30 seconds for a user to authenticate

        # TODO: create jwt for continue access token?
        self.state.continue_access_token = get_hex_uuid4()
        continue_response = Continue(
            uri=cast(AnyUrl, continue_url),
            wait=wait,
            access_token=ContinueAccessToken(value=self.state.continue_access_token),
        )
        self.state.grant_response.continue_ = continue_response
        self.state.grant_response.interact = interaction_response
        res = await transaction_state_db.save(self.state, expires_in=self.config.transaction_state_expires_in)
        logger.debug(f'state {self.state} saved: {res}')
        return self.state.grant_response

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if not self.state.proof_ok:
            return None

        # Create claims
        claims = await self.create_claims()

        # Create access token
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
        token.make_signed_token(key=self.signing_key)
        auth_response = GrantResponse(
            access_token=AccessTokenResponse(
                flags=[AccessTokenFlags.BEARER], access=self.state.requested_access, value=token.serialize()
            )
        )
        logger.info(f'OK:{self.state.key_reference}:{self.config.auth_token_audience}')
        logger.debug(f'claims: {claims}')
        return auth_response


class TestFlow(CommonFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> TestState:
        return TestState.from_dict(state=state)

    async def check_proof(self, gnap_key: Key, gnap_request: Optional[Union[GrantRequest, ContinueRequest]]) -> bool:
        if gnap_key.proof is Proof.TEST:
            logger.warning(f'TEST_MODE - access token will be returned with no proof')
            return True
        return False

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.state.grant_request.client, Client)
        assert isinstance(self.state.grant_request.client.key, Key)

        self.state.proof_ok = await self.check_proof(self.state.grant_request.client.key, self.state.grant_request)
        if not self.state.proof_ok:
            # try any other supported proof method, used in tests
            self.state.proof_ok = await super().check_proof(
                self.state.grant_request.client.key, self.state.grant_request
            )
        return None

    async def create_claims(self) -> Claims:
        claims = await super().create_claims()
        claims.source = 'test mode'
        return claims


class ConfigFlow(CommonFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> ConfigState:
        return ConfigState.from_dict(state=state)

    async def create_claims(self) -> ConfigClaims:
        base_claims = await super().create_claims()
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
        key_reference = self.state.grant_request.client.key
        self.state.key_reference = key_reference  # Remember the key reference for later use
        client_key = await lookup_client_key_from_config(key_reference=key_reference)
        if client_key is None:
            raise NextFlowException(status_code=400, detail='no client key found')

        logger.debug(f'key by reference found: {client_key}')
        self.state.grant_request.client.key = client_key
        # Load any claims associated with the key
        if self.state.key_reference in self.config.client_keys:  # please mypy
            self.state.config_claims = self.config.client_keys[self.state.key_reference].claims
        return None


class OnlyMTLSProofFlow(CommonFlow):
    async def check_proof(self, gnap_key: Key, gnap_request: Optional[Union[GrantRequest, ContinueRequest]]) -> bool:
        if gnap_key.proof is not Proof.MTLS:
            raise NextFlowException(status_code=400, detail='MTLS is the only supported proof method')
        return await check_mtls_proof(gnap_key=self.state.grant_request.client.key, cert=self.state.tls_client_cert)

    async def validate_proof(self) -> Optional[GrantResponse]:
        await super().validate_proof()
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

    async def create_claims(self) -> MDQClaims:
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

        base_claims = await super().create_claims()
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


class TLSFEDFlow(OnlyMTLSProofFlow):
    @classmethod
    def load_state(cls, state: Mapping[str, Any]) -> TLSFEDState:
        return TLSFEDState.from_dict(state=state)

    async def create_claims(self) -> TLSFEDClaims:
        if not self.state.entity:
            raise NextFlowException(status_code=400, detail='missing metadata entity')

        # Get scopes from metadata
        scopes = None
        if self.state.entity.extensions and self.state.entity.extensions.saml_scope:
            scopes = self.state.entity.extensions.saml_scope.scope

        base_claims = await super().create_claims()
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
