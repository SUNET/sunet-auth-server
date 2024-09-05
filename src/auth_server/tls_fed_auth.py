# -*- coding: utf-8 -*-
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Mapping, Optional
from uuid import uuid4

import aiohttp
from aiofiles import open as async_open
from async_lru import alru_cache
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto import jwk, jws
from loguru import logger
from pydantic import BaseModel, ConfigDict, ValidationError

from auth_server.cert_utils import rfc8705_fingerprint
from auth_server.config import load_config
from auth_server.models.gnap import Key, Proof, ProofMethod
from auth_server.models.tls_fed_metadata import Entity
from auth_server.models.tls_fed_metadata import Model as TLSFEDMetadataModel
from auth_server.models.tls_fed_metadata import TLSFEDJOSEHeader
from auth_server.time_utils import utc_now

__author__ = "lundberg"


class MetadataSource(BaseModel):
    issued_at: datetime
    expires_at: datetime
    issuer: str
    metadata: TLSFEDMetadataModel


class MetadataEntity(Entity):
    issuer: str
    model_config = ConfigDict(frozen=True)


class IssuerMetadata(BaseModel):
    issued_at: datetime
    renew_at: datetime
    expires_at: datetime
    entities: Mapping[str, MetadataEntity]
    model_config = ConfigDict(frozen=True)


class Metadata(BaseModel):
    issuer_metadata: Mapping[str, IssuerMetadata]
    model_config = ConfigDict(frozen=True)


async def load_jwks(path: Path) -> Optional[jwk.JWKSet]:
    try:
        with open(path, "r") as f:
            jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f"jwks loaded from {path}")
        return jwks
    except IOError as e:
        logger.error(f"Could not open {path}: {e}")
    return None


async def get_remote_metadata(url: str) -> Optional[str]:
    # Get remote metadata jws
    session = aiohttp.ClientSession()
    logger.debug(f"Trying {url}")
    try:
        response = await session.get(url=url)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        logger.exception(f"Failed to get remote metadata from {url}")
        return None
    if response.status != 200:
        logger.error(f"{url} returned {response.status}")
        return None
    text = await response.text()
    logger.debug(f"Received {text}")
    await session.close()
    return text


async def get_local_metadata(path: Path) -> Optional[str]:
    # Open local jws file
    try:
        async with async_open(path, "r") as f:
            return await f.read()
    except IOError as e:
        logger.error(f"Could not open {path}: {e}")
    return None


async def load_metadata_source(
    raw_jws: Optional[str], jwks: Optional[jwk.JWKSet], strict: bool = True
) -> Optional[MetadataSource]:
    if raw_jws is None:
        logger.warning("could not load metadata. missing jws")
        return None
    if jwks is None:
        logger.warning("could not load metadata. missing jwks")
        return None

    _jws = jws.JWS()

    try:
        # deserialize jws
        _jws.deserialize(raw_jws=raw_jws)
    except (jws.InvalidJWSObject, IndexError):
        logger.exception("metadata could not be deserialized")
        return None

    # load JOSE headers
    headers = []
    logger.debug(f"jose_header: {_jws.jose_header}")
    if isinstance(_jws.jose_header, list):
        for item in _jws.jose_header:
            headers.append(item)
    elif isinstance(_jws.jose_header, dict):
        headers.append(_jws.jose_header)

    jose_headers = []
    for item in headers:
        try:
            jose_headers.append(TLSFEDJOSEHeader.model_validate(item))
        except ValidationError:
            logger.exception("header could not be validated")
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
            logger.debug("invalid JWS signature")
            continue

    if not verified:
        logger.exception("metadata could not be verified")
        return None

    # validate jws
    assert jose_header is not None  # please mypy
    logger.debug(f"payload: {_jws.payload}")
    try:
        # validate payload structure
        metadata = TLSFEDMetadataModel.model_validate_json(_jws.payload)
        return MetadataSource(
            issued_at=jose_header.iat, expires_at=jose_header.exp, issuer=jose_header.iss, metadata=metadata
        )
    except ValidationError:
        logger.exception("metadata could not be validated")
        # if strict we do not try to load partial metadata
        if strict:
            return None

    # Try to load any entities that validates
    payload = json.loads(_jws.payload)
    # split out entities to load them one by one
    entities = payload.pop("entities")
    payload["entities"] = []  # entities can not be missing
    try:
        metadata = TLSFEDMetadataModel.model_validate(payload)
    except ValidationError:
        logger.exception("partial metadata could not be validated")
        # if there is something wrong with the base structure of the metadata, give up
        return None

    # validate entities and discard the ones failing
    for entity in entities:
        try:
            metadata.entities.append(Entity.model_validate(entity))
        except ValidationError:
            logger.exception(f'Failed to parse {entity.get("entity_id")} from {jose_header.iss} metadata')
            continue

    return MetadataSource(
        issued_at=jose_header.iat, expires_at=jose_header.exp, issuer=jose_header.iss, metadata=metadata
    )


async def load_metadata(metadata_sources: List[MetadataSource], cache_ttl: timedelta) -> Metadata:
    now = utc_now()
    renew_at = now + cache_ttl  # Set default renew time
    loaded_metadata: dict[str, IssuerMetadata] = {}
    for metadata_source in metadata_sources:
        # Set renew_at to the issuer's cache_ttl if available
        if metadata_source.metadata.cache_ttl is not None:
            renew_at = now + timedelta(seconds=metadata_source.metadata.cache_ttl)
        logger.info(f"metadata from {metadata_source.issuer} should be renewed at {renew_at}")
        # Parse entities
        entities = {}
        for entity in metadata_source.metadata.entities:
            entities[str(entity.entity_id)] = MetadataEntity(
                issuer=metadata_source.issuer,
                expires_at=metadata_source.expires_at,
                **entity.model_dump(exclude_unset=True),
            )
        key = metadata_source.issuer
        if key is None:
            key = str(uuid4())
        loaded_metadata[key] = IssuerMetadata(
            issuer=metadata_source.issuer,
            issued_at=metadata_source.issued_at,
            renew_at=renew_at,
            expires_at=metadata_source.expires_at,
            entities=entities,
        )
    return Metadata(issuer_metadata=loaded_metadata)


@alru_cache
async def get_tls_fed_metadata() -> Metadata:
    config = load_config()
    metadata_sources = []
    for source in config.tls_fed_metadata:
        logger.debug(f"trying to load metadata using: {source}")
        raw_jws = None
        jwks = await load_jwks(source.jwks)
        # Try local source if it exists
        if source.local is not None:
            raw_jws = await get_local_metadata(source.local)
            logger.debug(f"{source.local} returned jws: {raw_jws}")
        # if local source didn't return any metadata try remote source if it exists
        elif source.remote is not None:
            raw_jws = await get_remote_metadata(str(source.remote))
            logger.debug(f"{source.remote} returned jws: {raw_jws}")
        metadata_source = await load_metadata_source(raw_jws=raw_jws, jwks=jwks, strict=source.strict)
        if metadata_source is not None:
            logger.debug(f"loaded metadata source: {metadata_source}")
            metadata_sources.append(metadata_source)
    return await load_metadata(metadata_sources=metadata_sources, cache_ttl=config.tls_fed_metadata_cache_ttl)


async def get_entity(entity_id: str) -> Optional[MetadataEntity]:
    metadata = await get_tls_fed_metadata()
    now = utc_now()

    for issuer, issuer_metadata in metadata.issuer_metadata.items():
        # Check if metadata should be refreshed or if it is missing entities
        if now > issuer_metadata.renew_at or not issuer_metadata.entities:
            logger.info(f"{issuer} metadata cache has expired {issuer_metadata.renew_at} or no entities found")
            logger.debug(f"Cache info: {get_tls_fed_metadata.cache_info()}")
            # clear lru_cache and reload metadata
            get_tls_fed_metadata.cache_clear()
            return await get_entity(entity_id=entity_id)

        # Check if metadata is valid
        # not before issued_at
        if now < issuer_metadata.issued_at:
            logger.error(f"Metadata for issuer {issuer} is not valid yet (issued at {issuer_metadata.issued_at})")
            continue
        # not after expires_at
        if now > issuer_metadata.expires_at:
            logger.error(f"Metadata for issuer {issuer} has expired {issuer_metadata.expires_at}")
            continue

        # Get entity from metadata
        entity = issuer_metadata.entities.get(entity_id)
        if not entity:
            logger.info(f"{entity_id} not found in {issuer} metadata")
            continue

        return entity

    return None


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
        logger.info("Found cert in metadata")
        return Key(
            proof=Proof(method=ProofMethod.MTLS),
            cert_S256=rfc8705_fingerprint(certs[0]),
        )
    return None
