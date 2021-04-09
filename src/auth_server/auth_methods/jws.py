# -*- coding: utf-8 -*-

from auth_server.models.gnap import GrantRequest
from auth_server.models.jose import JWSHeaders

__author__ = 'lundberg'


async def check_jws_proof(grant_request: GrantRequest, jws_headers: JWSHeaders) -> bool:
    # TODO: implement
    return False


async def check_jwsd_proof(grant_request: GrantRequest, detached_jws: str) -> bool:
    # TODO: implement
    return False
