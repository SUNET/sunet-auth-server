# -*- coding: utf-8 -*-
import logging
from base64 import b64encode
from collections import OrderedDict as _OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, List, Mapping, Optional, OrderedDict, Sequence, Union

import aiohttp
import xmltodict
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, Hash
from cryptography.x509 import Certificate, load_pem_x509_certificate
from pyexpat import ExpatError

__author__ = 'lundberg'

from auth_server.models.gnap import Key, Proof

logger = logging.getLogger(__name__)


def get_values(key: str, obj: Union[Mapping, Sequence]) -> Iterable[Any]:
    """
    Recurse through a dict like object and return all values for the specified key

    :param key: key to look for
    :param obj: structure to search in
    :return: iterator of values
    """
    if isinstance(obj, dict):
        if key in obj:
            yield obj[key]
        for value in obj.values():
            for hit in get_values(key, value):
                yield hit
    elif isinstance(obj, list):
        for item in obj:
            for hit in get_values(key, item):
                yield hit


class KeyUse(Enum):
    SIGNING = 'signing'
    ENCRYPTION = 'encryption'


@dataclass(frozen=True)
class MDQCert:
    use: KeyUse
    cert: Certificate


@dataclass(frozen=True)
class MDQData:
    certs: List[MDQCert] = field(default_factory=list)
    metadata: OrderedDict = field(default_factory=_OrderedDict)


async def xml_mdq_get(entity_id: str, mdq_url: str) -> MDQData:
    # SHA1 hash and create hex representation of entity id
    digest = Hash(SHA1())
    digest.update(entity_id.encode())
    identifier = f'{{sha1}}{digest.finalize().hex()}'
    logger.debug(f'mdq identifier: {identifier}')

    # Get xml from the MDQ service
    headers = {'Accept': 'application/samlmetadata+xml'}
    session = aiohttp.ClientSession()
    url = f'{mdq_url}/{identifier}'
    logger.debug(f'Trying {url}')
    response = await session.get(url=url, headers=headers)
    await session.close()
    if response.status != 200:
        logger.error(f'{mdq_url}/{identifier} returned {response.status}')
        return MDQData()

    xml = await response.text()
    # Parse the xml to a OrderedDict and grab the certs and their use
    # TODO: Grab other interesting things from the metadata
    try:
        # TODO: Should we use defusedxml.expatbuilder?
        entity = xmltodict.parse(xml, process_namespaces=True)
        certs = []
        # Certs
        for key_descriptor in get_values(key='urn:oasis:names:tc:SAML:2.0:metadata:KeyDescriptor', obj=entity):
            use = list(get_values(key='@use', obj=key_descriptor))[0]
            raw_cert = list(get_values(key='http://www.w3.org/2000/09/xmldsig#:X509Certificate', obj=key_descriptor))[0]
            raw_cert = f'-----BEGIN CERTIFICATE-----\n{raw_cert}\n-----END CERTIFICATE-----'
            cert = load_pem_x509_certificate(raw_cert.encode())
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
            proof=Proof.MTLS, cert_S256=b64encode(signing_cert[0].fingerprint(algorithm=SHA256())).decode('utf-8'),
        )
    return None
