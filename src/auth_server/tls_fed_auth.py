# -*- coding: utf-8 -*-
import base64
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Mapping, Optional

import aiohttp
from aiofile import async_open
from async_lru import alru_cache
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto import jwk, jws
from pydantic import BaseModel, ValidationError

from auth_server.config import load_config
from auth_server.models.gnap import Key, Proof
from auth_server.models.tls_fed_metadata import Entity
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadataModel
from auth_server.models.tls_fed_metadata import TLSFEDJOSEHeader
from auth_server.time_utils import utc_now

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class MetadataSource(BaseModel):
    issued_at: datetime
    expires_at: datetime
    issuer: str
    metadata: TLSFEDMetadataModel


class MetadataEntity(Entity):
    issuer: str
    expires_at: datetime
    # organization_id should be part of the Entity schema
    organization_id: str


class Metadata(BaseModel):
    renew_at: datetime
    entities: Mapping[str, MetadataEntity]

    class Config:
        frozen = True


async def load_jwks(path: Path) -> Optional[jwk.JWKSet]:
    try:
        with open(path, 'r') as f:
            jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f'jwks loaded from {path}')
        return jwks
    except IOError as e:
        logger.error(f'Could not open {path}: {e}')
    return None


async def get_remote_metadata(url: str) -> Optional[str]:
    # Get remote metadata jws
    session = aiohttp.ClientSession()
    logger.debug(f'Trying {url}')
    try:
        response = await session.get(url=url)
    except aiohttp.ClientError as e:
        logger.error(f'{url} failed: {e}')
        return None
    if response.status != 200:
        logger.error(f'{url} returned {response.status}')
        return None
    text = await response.text()
    logger.debug(f'Received {text}')
    await session.close()
    return text


async def get_local_metadata(path: Path) -> Optional[str]:
    # Open local jws file
    try:
        async with async_open(path, 'r') as f:
            return await f.read()
    except IOError as e:
        logger.error(f'Could not open {path}: {e}')
    return None


async def load_metadata_source(
    raw_jws: Optional[str], jwks: Optional[jwk.JWKSet], strict: bool = True
) -> Optional[MetadataSource]:
    if raw_jws is None:
        logger.warning('could not load metadata. missing jws')
        return None
    if jwks is None:
        logger.warning('could not load metadata. missing jwks')
        return None

    _jws = jws.JWS()

    try:
        # deserialize jws
        _jws.deserialize(raw_jws=raw_jws)
    except (jws.InvalidJWSObject, IndexError):
        logger.exception(f'metadata could not be deserialized')
        return None

    # load JOSE headers
    headers = []
    logger.debug(f'jose_header: {_jws.jose_header}')
    if isinstance(_jws.jose_header, list):
        for item in _jws.jose_header:
            headers.append(item)
    elif isinstance(_jws.jose_header, dict):
        headers.append(_jws.jose_header)

    jose_headers = []
    for item in headers:
        try:
            jose_headers.append(TLSFEDJOSEHeader.parse_obj(item))
        except ValidationError:
            logger.exception(f'header could not be validated')
            continue

    # verify jws
    verified = False
    jose_header = None
    for header in jose_headers:
        try:
            _jws.verify(key=jwks.get_key(kid=header.kid))
            verified = True
            jose_header = header
            break
        except jws.InvalidJWSSignature:
            logger.debug(f'')
            continue

    if not verified:
        logger.exception(f'metadata could not be verified')
        return None

    # validate jws
    assert jose_header is not None  # please mypy
    logger.debug(f'payload: {_jws.payload}')
    try:
        # validate payload structure
        metadata = TLSFEDMetadataModel.parse_raw(_jws.payload, encoding='utf-8')
        return MetadataSource(
            issued_at=jose_header.iat, expires_at=jose_header.exp, issuer=jose_header.iss, metadata=metadata
        )
    except ValidationError as e:
        logger.exception(f'metadata could not be validated')
        # if strict we do not try to load partial metadata
        if strict:
            return None

    # Try to load any entities that validates
    payload = json.loads(_jws.payload)
    # split out entities to load them one by one
    entities = payload.pop('entities')
    payload['entities'] = []  # entities can not be missing
    try:
        metadata = TLSFEDMetadataModel.parse_obj(payload)
    except ValidationError:
        logger.exception(f'partial metadata could not be validated')
        # if there is something wrong with the base structure of the metadata, give up
        return None

    # validate entities and discard the ones failing
    for entity in entities:
        try:
            metadata.entities.append(Entity.parse_obj(entity))
        except ValidationError:
            logger.exception(f'Failed to parse {entity.get("entity_id")} from {jose_header.iss} metadata')
            continue

    return MetadataSource(
        issued_at=jose_header.iat, expires_at=jose_header.exp, issuer=jose_header.iss, metadata=metadata
    )


async def load_metadata(metadata_sources: List[MetadataSource], max_age: timedelta) -> Metadata:
    # Set default renew and expire times
    renew_at = utc_now() + max_age
    entities = {}
    for metadata_source in metadata_sources:
        # please mypy
        assert metadata_source.metadata.cache_ttl is not None
        assert isinstance(metadata_source.metadata.cache_ttl, int)
        # Set renew_at to the earliest issue time + cache ttl or max age
        cache_ttl = timedelta(seconds=metadata_source.metadata.cache_ttl)
        if max_age <= cache_ttl:
            cache_ttl = max_age
        source_renew_at = metadata_source.issued_at + cache_ttl
        if source_renew_at < renew_at:
            renew_at = source_renew_at
            logger.info(f'metadata should be renewed at {renew_at}')
        # Collect entities from all sources
        for entity in metadata_source.metadata.entities:
            entities[str(entity.entity_id)] = MetadataEntity(
                issuer=metadata_source.issuer, expires_at=metadata_source.expires_at, **entity.dict(exclude_unset=True),
            )
    return Metadata(renew_at=renew_at, entities=entities)


@alru_cache
async def get_tls_fed_metadata() -> Metadata:
    config = load_config()
    metadata_sources = []
    for source in config.tls_fed_metadata:
        logger.debug(f'trying to load metadata using: {source}')
        raw_jws = None
        jwks = await load_jwks(source.jwks)
        # Try local source if it exists
        if source.local is not None:
            raw_jws = await get_local_metadata(source.local)
            logger.debug(f'{source.local} returned jws: {raw_jws}')
        # if local source didn't return any metadata try remote source if it exists
        elif source.remote is not None and raw_jws is None:
            raw_jws = await get_remote_metadata(source.remote)
            logger.debug(f'{source.remote} returned jws: {raw_jws}')
        metadata_source = await load_metadata_source(raw_jws=raw_jws, jwks=jwks, strict=source.strict)
        if metadata_source is not None:
            logger.debug(f'loaded metadata source: {metadata_source}')
            metadata_sources.append(metadata_source)
    return await load_metadata(metadata_sources=metadata_sources, max_age=config.tls_fed_metadata_max_age)


async def get_entity(entity_id: str) -> Optional[MetadataEntity]:
    metadata = await get_tls_fed_metadata()
    now = utc_now()

    # Check if metadata should be refreshed
    if now > metadata.renew_at:
        # clear lru_cache and reload metadata
        get_tls_fed_metadata.cache_clear()
        metadata = await get_tls_fed_metadata()

    if not metadata.entities:
        logger.error('no metadata entities loaded')
        return None

    # Get entity from metadata
    entity = metadata.entities.get(entity_id)
    if not entity:
        logger.error(f'{entity_id} not found in metadata')
        return None

    # Check if entity has expired
    if now > entity.expires_at:
        logger.error(f'{entity_id} expired {entity.expires_at}')
        return None

    return entity


async def entity_to_key(entity: Optional[MetadataEntity]) -> Optional[Key]:
    if entity is None:
        return None

    certs = [
        load_pem_x509_certificate(item.x509certificate.encode())
        for item in entity.issuers
        if item.x509certificate is not None
    ]
    if certs:
        # TODO: how do we handle multiple certs?
        logger.info(f'Found cert in metadata')
        return Key(
            proof=Proof.MTLS, cert_S256=base64.b64encode(certs[0].fingerprint(algorithm=SHA256())).decode('utf-8'),
        )
    return None
