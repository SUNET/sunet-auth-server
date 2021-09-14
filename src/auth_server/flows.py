# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from fastapi import HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK

from auth_server.config import AuthServerConfig, ConfigurationError
from auth_server.context import ContextRequest
from auth_server.mdq import MDQData, mdq_data_to_key, xml_mdq_get
from auth_server.models.claims import Claims, ConfigClaims, MDQClaims, TLSFEDClaims
from auth_server.models.gnap import (
    Access,
    AccessTokenFlags,
    AccessTokenResponse,
    Client,
    GrantRequest,
    GrantResponse,
    Key,
    Proof,
)
from auth_server.models.tls_fed_metadata import RegisteredExtensions
from auth_server.proof.common import lookup_client_key_from_config
from auth_server.proof.jws import check_jws_proof, check_jwsd_proof
from auth_server.proof.mtls import check_mtls_proof
from auth_server.tls_fed_auth import MetadataEntity, entity_to_key, get_entity
from auth_server.utils import get_values

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class BuiltInFlow(str, Enum):
    FULLFLOW = 'FullFlow'
    MDQFLOW = 'MDQFlow'
    TLSFEDFLOW = 'TLSFEDFlow'
    TESTFLOW = 'TestFlow'
    CONFIGFLOW = 'ConfigFlow'


# Use this to go to next flow
class NextFlowException(HTTPException):
    pass


# Use this to return an error message to the client
class StopTransactionException(HTTPException):
    pass


class BaseAuthFlow:
    def __init__(
        self,
        request: ContextRequest,
        grant_req: GrantRequest,
        config: AuthServerConfig,
        signing_key: JWK,
        tls_client_cert: Optional[str] = None,
        detached_jws: Optional[str] = None,
    ):
        grant_req_in = grant_req.copy(deep=True)  # let every flow have their own copy of the grant request

        self.request = request
        self.grant_request = grant_req_in
        self.config = config
        self.signing_key = signing_key
        self.tls_client_cert = tls_client_cert
        self.detached_jws = detached_jws
        self.proof_ok: bool = False
        self.requested_access: List[Union[str, Access]] = []
        self.grant_response: Optional[GrantResponse] = None
        self.mdq_data: Optional[MDQData] = None
        self.config_claims: Dict[str, Any] = {}

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
            'create_auth_token',
        ]

    async def _create_claims(self) -> Claims:
        return Claims(
            iss=self.config.auth_token_issuer,
            exp=self.config.auth_token_expires_in,
            aud=self.config.auth_token_audience,
            sub=self.request.context.key_reference,
            requested_access=self.requested_access,
        )

    async def lookup_client(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def validate_proof(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def handle_access(self) -> Optional[GrantResponse]:
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


class CommonFlow(BaseAuthFlow):
    """
    Gather current flow rules and implementation limitations here
    """

    async def lookup_client(self) -> Optional[GrantResponse]:
        if not isinstance(self.grant_request.client, Client):
            raise NextFlowException(status_code=400, detail='client by reference not implemented')
        return None

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, Key):
            raise NextFlowException(status_code=400, detail='key by reference not supported')
        return None

    async def handle_access_token(self) -> Optional[GrantResponse]:
        if isinstance(self.grant_request.access_token, list):
            if len(self.grant_request.access_token) > 1:
                raise NextFlowException(status_code=400, detail='multiple access token requests not supported')
            self.grant_request.access_token = self.grant_request.access_token[0]
        # TODO: How do we want to validate the access request?
        if self.grant_request.access_token.access:
            self.requested_access = self.grant_request.access_token.access
        return None

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if not self.proof_ok:
            return None

        # Create claims
        claims = await self._create_claims()

        # Create access token
        token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
        token.make_signed_token(self.signing_key)
        auth_response = GrantResponse(
            access_token=AccessTokenResponse(
                flags=[AccessTokenFlags.BEARER], access=self.requested_access, value=token.serialize()
            )
        )
        logger.info(f'OK:{self.request.context.key_reference}:{self.config.auth_token_audience}')
        logger.debug(f'claims: {claims}')
        return auth_response


class FullFlow(CommonFlow):
    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)

        # First look for a key in config
        if isinstance(self.grant_request.client.key, str):
            # Key sent by reference, look it up
            logger.info('Looking up key in config')
            logger.debug(f'key reference: {self.grant_request.client.key}')
            client_key = await lookup_client_key_from_config(request=self.request, key_id=self.grant_request.client.key)
            if client_key is not None:
                self.grant_request.client.key = client_key
        # if mdq is configured, try it
        if isinstance(self.grant_request.client.key, str) and self.config.mdq_server is not None:
            logger.info(f'Trying to load key from mdq')
            self.mdq_data = await xml_mdq_get(entity_id=self.grant_request.client.key, mdq_url=self.config.mdq_server)
            client_key = await mdq_data_to_key(self.mdq_data)
            if client_key is not None:
                self.grant_request.client.key = client_key

        # If the key is still a reference give up and call the next flow
        if not isinstance(self.grant_request.client.key, Key):
            raise NextFlowException(status_code=400, detail='no client key found')

        return None

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        # MTLS
        if self.grant_request.client.key.proof is Proof.MTLS:
            if not self.tls_client_cert:
                raise NextFlowException(status_code=400, detail='no client certificate found')
            self.proof_ok = await check_mtls_proof(grant_request=self.grant_request, cert=self.tls_client_cert)
        # HTTPSIGN
        elif self.grant_request.client.key.proof is Proof.HTTPSIGN:
            raise NextFlowException(status_code=400, detail='httpsign is not implemented')
        # JWS
        elif self.grant_request.client.key.proof is Proof.JWS:
            self.proof_ok = await check_jws_proof(
                request=self.request, grant_request=self.grant_request, jws_header=self.request.context.jws_header
            )
        # JWSD
        elif self.grant_request.client.key.proof is Proof.JWSD:
            if not self.detached_jws:
                raise NextFlowException(status_code=400, detail='no detached jws header found')
            self.proof_ok = await check_jwsd_proof(
                request=self.request, grant_request=self.grant_request, detached_jws=self.detached_jws
            )
        else:
            raise NextFlowException(status_code=400, detail='no supported proof method')
        return None


class TestFlow(FullFlow):
    async def _create_claims(self) -> Claims:
        claims = await super()._create_claims()
        claims.source = 'test mode'
        return claims

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        if self.grant_request.client.key.proof is Proof.TEST:
            logger.warning(f'TEST_MODE - access token will be returned with no proof')
            self.proof_ok = True
        return None


class ConfigFlow(FullFlow):
    async def _create_claims(self) -> ConfigClaims:
        base_claims = await super()._create_claims()
        # Update the claims with any claims found in config for this key
        claims_dict = base_claims.dict(exclude_none=True)
        claims_dict.update(self.config_claims)
        if 'source' not in claims_dict:
            claims_dict['source'] = 'config'
        return ConfigClaims(**claims_dict)

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        logger.info('Looking up key in config')
        logger.debug(f'key reference: {self.grant_request.client.key}')
        client_key = await lookup_client_key_from_config(request=self.request, key_id=self.grant_request.client.key)
        if client_key is None:
            raise NextFlowException(status_code=400, detail='no client key found')

        logger.debug(f'key by reference found: {client_key}')
        self.grant_request.client.key = client_key
        # Load any claims associated with the key
        if self.request.context.key_reference in self.config.client_keys:  # please mypy
            self.config_claims = self.config.client_keys[self.request.context.key_reference].claims
        return None


class OnlyMTLSProofFlow(CommonFlow):
    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        if self.grant_request.client.key.proof is not Proof.MTLS:
            raise NextFlowException(status_code=400, detail='MTLS is the only supported proof method')
        if not self.tls_client_cert:
            raise NextFlowException(status_code=400, detail='no client certificate found')

        self.proof_ok = await check_mtls_proof(grant_request=self.grant_request, cert=self.tls_client_cert)
        if not self.proof_ok:
            raise NextFlowException(status_code=401, detail='no client certificate found')
        return None


class MDQFlow(OnlyMTLSProofFlow):
    async def _create_claims(self) -> MDQClaims:
        if not self.mdq_data:
            raise NextFlowException(status_code=400, detail='missing mdq data')

        # Get data from metadata
        # entity id
        entity_descriptor = list(
            get_values('urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor', self.mdq_data.metadata)
        )
        try:
            entity_id = entity_descriptor[0]['@entityID']
        except (IndexError, KeyError):
            raise NextFlowException(status_code=401, detail='malformed metadata')
        # scopes
        scopes = []
        for scope in get_values('urn:mace:shibboleth:metadata:1.0:Scope', self.mdq_data.metadata):
            scopes.append(scope['#text'])
        # source
        registration_info = list(
            get_values('urn:oasis:names:tc:SAML:metadata:rpi:RegistrationInfo', self.mdq_data.metadata)
        )
        try:
            source = registration_info[0]['@registrationAuthority']
        except (IndexError, KeyError):
            source = self.config.mdq_server  # Default source to mdq server if registrationAuthority is not set

        base_claims = await super()._create_claims()
        return MDQClaims(**base_claims.dict(exclude_none=True), entity_id=entity_id, scopes=scopes, source=source)

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        key_id = self.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if self.config.mdq_server is None:
            raise ConfigurationError('mdq_server not configured')

        # Look for a key using mdq
        logger.info(f'Trying to load key from mdq')
        self.mdq_data = await xml_mdq_get(entity_id=key_id, mdq_url=self.config.mdq_server)
        client_key = await mdq_data_to_key(self.mdq_data)

        if not client_key:
            raise NextFlowException(status_code=400, detail=f'no client key found for {key_id}')
        self.grant_request.client.key = client_key
        return None


class TLSFEDFlow(OnlyMTLSProofFlow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.entity: Optional[MetadataEntity] = None

    async def _create_claims(self) -> TLSFEDClaims:
        if not self.entity:
            raise NextFlowException(status_code=400, detail='missing metadata entity')

        # Get scopes from metadata
        scopes = None
        if self.entity.extensions and self.entity.extensions.get(RegisteredExtensions.SAML_SCOPE):
            scopes = self.entity.extensions[RegisteredExtensions.SAML_SCOPE].scope

        base_claims = await super()._create_claims()
        return TLSFEDClaims(
            **base_claims.dict(exclude_none=True),
            entity_id=self.entity.entity_id,
            scopes=scopes,
            organization_id=self.entity.organization_id,
            source=self.entity.issuer,
        )

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonFlow or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, str):
            raise NextFlowException(status_code=400, detail='key by reference is mandatory')

        key_id = self.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if not self.config.tls_fed_metadata:
            raise ConfigurationError('TLS fed auth not configured')

        # Look for a key in the TLS fed metadata
        logger.info(f'Trying to load key from TLS fed auth')
        self.entity = await get_entity(entity_id=key_id)
        client_key = await entity_to_key(self.entity)

        if not client_key:
            raise NextFlowException(status_code=400, detail=f'no client key found for {key_id}')
        self.grant_request.client.key = client_key
        return None
