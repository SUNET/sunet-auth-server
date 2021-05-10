# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from abc import ABC
from typing import Optional

from fastapi import HTTPException
from jwcrypto import jwt
from jwcrypto.jwk import JWK

from auth_server.config import AuthServerConfig, ConfigurationError
from auth_server.context import ContextRequest
from auth_server.mdq import MDQData, mdq_data_to_key, xml_mdq_get
from auth_server.models.gnap import AccessTokenResponse, Client, GrantRequest, GrantResponse, Key, Proof
from auth_server.models.jose import Claims, MDQClaims, TLSFEDClaims
from auth_server.proof.common import lookup_client_key_from_config
from auth_server.proof.jws import check_jws_proof, check_jwsd_proof
from auth_server.proof.mtls import check_mtls_proof
from auth_server.tls_fed_auth import MetadataEntity, entity_to_key, get_entity
from auth_server.utils import get_values

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class BaseAuthFlow(ABC):
    def __init__(
        self,
        request: ContextRequest,
        grant_req: GrantRequest,
        config: AuthServerConfig,
        signing_key: JWK,
        tls_client_cert: Optional[str] = None,
        detached_jws: Optional[str] = None,
    ):
        self.request = request
        self.grant_request = grant_req
        self.config = config
        self.signing_key = signing_key
        self.tls_client_cert = tls_client_cert
        self.detached_jws = detached_jws
        self.proof_ok: bool = False
        self.grant_response: Optional[GrantResponse] = None
        self.mdq_data: Optional[MDQData] = None

    @staticmethod
    async def steps():
        # This is the order the methods in the flow will be called
        return ['lookup_client', 'lookup_client_key', 'validate_proof', 'create_auth_token']

    async def lookup_client(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def validate_proof(self) -> Optional[GrantResponse]:
        raise NotImplementedError()

    async def create_auth_token(self) -> Optional[GrantResponse]:
        raise NotImplementedError()


class CommonRules(BaseAuthFlow):
    """
    Gather current flow rules and implementation limitations here
    """

    async def lookup_client(self) -> Optional[GrantResponse]:
        if not isinstance(self.grant_request.client, Client):
            raise HTTPException(status_code=400, detail='client by reference not implemented')
        return None


class FullFlow(CommonRules):
    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
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
        return None

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        # MTLS
        if self.grant_request.client.key.proof is Proof.MTLS:
            if self.tls_client_cert is None:
                raise HTTPException(status_code=400, detail='no client certificate found')
            self.proof_ok = await check_mtls_proof(grant_request=self.grant_request, cert=self.tls_client_cert)
        # HTTPSIGN
        elif self.grant_request.client.key.proof is Proof.HTTPSIGN:
            raise HTTPException(status_code=400, detail='httpsign is not implemented')
        # JWS
        elif self.grant_request.client.key.proof is Proof.JWS:
            self.proof_ok = await check_jws_proof(
                request=self.request, grant_request=self.grant_request, jws_header=self.request.context.jws_header
            )
        # JWSD
        elif self.grant_request.client.key.proof is Proof.JWSD:
            if self.detached_jws is None:
                raise HTTPException(status_code=400, detail='no detached jws header found')
            self.proof_ok = await check_jwsd_proof(
                request=self.request, grant_request=self.grant_request, detached_jws=self.detached_jws
            )
        else:
            raise HTTPException(status_code=400, detail='no supported proof method')
        return None

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if self.proof_ok:
            # Create access token
            claims = Claims(exp=self.config.auth_token_expires_in, aud=self.config.auth_token_audience)
            token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
            token.make_signed_token(self.signing_key)
            auth_response = GrantResponse(access_token=AccessTokenResponse(bound=False, value=token.serialize()))
            logger.info(f'OK:{self.request.context.key_reference}:{self.config.auth_token_audience}')
            return auth_response
        return None


class TestFlow(FullFlow):
    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        if self.grant_request.client.key.proof is Proof.TEST:
            logger.warning(f'TEST_MODE - access token will be returned with no proof')
            self.proof_ok = True
        return None


class MDQFlow(CommonRules):
    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, str):
            raise HTTPException(status_code=400, detail='key by reference is mandatory')

        key_id = self.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if self.config.mdq_server is None:
            raise ConfigurationError('mdq_server not configured')

        # Look for a key using mdq
        logger.info(f'Trying to load key from mdq')
        self.mdq_data = await xml_mdq_get(entity_id=key_id, mdq_url=self.config.mdq_server)
        client_key = await mdq_data_to_key(self.mdq_data)

        if not client_key:
            raise HTTPException(status_code=400, detail=f'no client key found for {key_id}')
        self.grant_request.client.key = client_key
        return None

    async def validate_proof(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
        assert isinstance(self.grant_request.client, Client)
        assert isinstance(self.grant_request.client.key, Key)

        if self.grant_request.client.key.proof is not Proof.MTLS:
            raise HTTPException(status_code=400, detail='MTLS is the only supported proof method')
        if self.tls_client_cert is None:
            raise HTTPException(status_code=400, detail='no client certificate found')

        self.proof_ok = await check_mtls_proof(grant_request=self.grant_request, cert=self.tls_client_cert)
        if not self.proof_ok:
            raise HTTPException(status_code=401, detail='no client certificate found')
        return None

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if self.proof_ok and self.mdq_data:
            # Get data from metadata
            # entity id
            entity_descriptor = list(
                get_values('urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor', self.mdq_data.metadata)
            )
            try:
                entity_id = entity_descriptor[0]['@entityID']
            except (IndexError, KeyError):
                raise HTTPException(status_code=401, detail='malformed metadata')
            # scopes
            scopes = []
            for scope in get_values('urn:mace:shibboleth:metadata:1.0:Scope', self.mdq_data.metadata):
                scopes.append(scope['#text'])

            # Create access token
            claims = MDQClaims(
                exp=self.config.auth_token_expires_in,
                aud=self.config.auth_token_audience,
                entity_id=entity_id,
                scopes=scopes,
            )
            token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
            token.make_signed_token(self.signing_key)
            auth_response = GrantResponse(access_token=AccessTokenResponse(bound=False, value=token.serialize()))
            logger.info(f'OK:{self.request.context.key_reference}:{self.config.auth_token_audience}')
            return auth_response
        return None


class TLSFEDFlow(MDQFlow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.entity: Optional[MetadataEntity] = None

    async def lookup_client_key(self) -> Optional[GrantResponse]:
        # please mypy, enforced in CommonRules or previous steps
        assert isinstance(self.grant_request.client, Client)

        if not isinstance(self.grant_request.client.key, str):
            raise HTTPException(status_code=400, detail='key by reference is mandatory')

        key_id = self.grant_request.client.key
        logger.debug(f'key reference: {key_id}')

        if not self.config.tls_fed_metadata:
            raise ConfigurationError('TLS fed auth not configured')

        # Look for a key in the TLS fed metadata
        logger.info(f'Trying to load key from TLS fed auth')
        self.entity = await get_entity(entity_id=key_id)
        client_key = await entity_to_key(self.entity)

        if not client_key:
            raise HTTPException(status_code=400, detail=f'no client key found for {key_id}')
        self.grant_request.client.key = client_key
        return None

    async def create_auth_token(self) -> Optional[GrantResponse]:
        if self.proof_ok and self.entity:
            # Create access token
            claims = TLSFEDClaims(
                exp=self.config.auth_token_expires_in,
                aud=self.config.auth_token_audience,
                entity_id=self.entity.entity_id,
                scopes=self.entity.scopes,
                organization_id=self.entity.organization_id,
            )
            token = jwt.JWT(header={'alg': 'ES256'}, claims=claims.to_rfc7519())
            token.make_signed_token(self.signing_key)
            auth_response = GrantResponse(access_token=AccessTokenResponse(bound=False, value=token.serialize()))
            logger.info(f'OK:{self.request.context.key_reference}:{self.config.auth_token_audience}')
            return auth_response
        return None
