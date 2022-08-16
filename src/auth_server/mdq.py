# -*- coding: utf-8 -*-
import logging
from base64 import b64encode
from collections import OrderedDict as _OrderedDict
from enum import Enum
from typing import TYPE_CHECKING, List, Optional, OrderedDict, Union

import aiohttp
import xmltodict
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.x509 import Certificate
from pydantic import BaseModel, Field, validator
from pyexpat import ExpatError

if TYPE_CHECKING:
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny, DictStrAny

from auth_server.models.gnap import Key, ProofMethod
from auth_server.utils import get_values, hash_with, load_cert_from_str, serialize_certificate

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


class KeyUse(str, Enum):
    SIGNING = 'signing'
    ENCRYPTION = 'encryption'


class MDQBase(BaseModel):
    class Config:
        allow_mutation = False  # should not change after load
        arbitrary_types_allowed = True  # needed for x509.Certificate
        json_encoders = {Certificate: serialize_certificate}


class MDQCert(MDQBase):
    use: KeyUse
    cert: Certificate

    @validator('cert', pre=True)
    def deserialize_cert(cls, v: str) -> Certificate:
        if isinstance(v, Certificate):
            return v
        return load_cert_from_str(v)

    def dict(
        self,
        *,
        include: Union['AbstractSetIntStr', 'MappingIntStrAny'] = None,
        exclude: Union['AbstractSetIntStr', 'MappingIntStrAny'] = None,
        by_alias: bool = False,
        skip_defaults: bool = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
    ) -> 'DictStrAny':
        # serialize Certificate on dict use
        d = super().dict(
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            skip_defaults=skip_defaults,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
        )
        d['cert'] = serialize_certificate(d['cert'])
        return d


class MDQData(MDQBase):
    certs: List[MDQCert] = Field(default_factory=list)
    metadata: OrderedDict = Field(default_factory=_OrderedDict)


async def xml_mdq_get(entity_id: str, mdq_url: str) -> MDQData:
    # SHA1 hash and create hex representation of entity id
    entity_id_hash = hash_with(SHA1(), entity_id.encode())
    identifier = f'{{sha1}}{entity_id_hash.hex()}'
    logger.debug(f'mdq identifier: {identifier}')

    # Get xml from the MDQ service
    headers = {'Accept': 'application/samlmetadata+xml'}
    session = aiohttp.ClientSession()
    url = f'{mdq_url}/{identifier}'
    logger.debug(f'Trying {url}')
    try:
        response = await session.get(url=url, headers=headers)
    except aiohttp.ClientError as e:
        logger.error(f'{url} failed: {e}')
        return MDQData()

    if response.status != 200:
        logger.error(f'{mdq_url}/{identifier} returned {response.status}')
        return MDQData()

    xml = await response.text()
    await session.close()
    # Parse the xml to a OrderedDict and grab the certs and their use
    try:
        # TODO: Should we use defusedxml.expatbuilder?
        entity = xmltodict.parse(xml, process_namespaces=True)
        certs = []
        # Certs
        for key_descriptor in get_values(key='urn:oasis:names:tc:SAML:2.0:metadata:KeyDescriptor', obj=entity):
            use = list(get_values(key='@use', obj=key_descriptor))[0]
            raw_cert = list(get_values(key='http://www.w3.org/2000/09/xmldsig#:X509Certificate', obj=key_descriptor))[0]
            cert = load_cert_from_str(raw_cert)
            certs.append(MDQCert(use=KeyUse(use), cert=cert))
        return MDQData(certs=certs, metadata=entity)
    except (ExpatError, ValueError):  # TODO: handle exceptions properly
        logger.exception(f'Failed to parse mdq entity: {entity_id}')
    return MDQData()


async def mdq_data_to_key(mdq_data: MDQData) -> Optional[Key]:
    signing_cert = [item.cert for item in mdq_data.certs if item.use == KeyUse.SIGNING]
    # There should only be one or zero signing certs
    if signing_cert:
        logger.info(f'Found cert in metadata')
        return Key(
            proof=ProofMethod.MTLS,
            cert_S256=b64encode(signing_cert[0].fingerprint(algorithm=SHA256())).decode('utf-8'),
        )
    return None
