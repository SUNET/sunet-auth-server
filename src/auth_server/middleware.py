# -*- coding: utf-8 -*-
import logging

from fastapi import HTTPException
from jwcrypto import jws
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Message

from auth_server.context import ContextRequestMixin
from auth_server.models.gnap import Client, GrantRequest, Key
from auth_server.models.jose import JWSHeaders

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


# middleware needs to return a reponse
# some background: https://github.com/tiangolo/fastapi/issues/458
def return_error_response(status_code: int, detail: str):
    return PlainTextResponse(status_code=status_code, content=detail)


# Hack to be able to get request body both now and later
# https://github.com/encode/starlette/issues/495#issuecomment-513138055
async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {'type': 'http.request', 'body': body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


class JOSEMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        request = self.make_context_request(request)
        if request.headers.get('content-type') == 'application/jose':
            logger.info('got application/jose request')
            client_key = None
            body = await get_body(request)
            logger.debug(f'body: {body}')
            jwstoken = jws.JWS()
            jwstoken.deserialize(body.decode('utf-8'))
            logger.info('JWS token deserialized')
            logger.debug(f'JWS: {jwstoken.objects}')

            # Use unverified data to get the public key
            unverified_grant_req = GrantRequest.parse_raw(jwstoken.objects.get('payload').decode('utf-8'))
            logger.debug(f'unverified grant request: {unverified_grant_req.dict(exclude_unset=True)}')

            if not isinstance(unverified_grant_req.client, Client):
                return return_error_response(status_code=400, detail='client by reference not implemented')
            # TODO: Handle key by reference
            if not isinstance(unverified_grant_req.client.key, Key):
                return return_error_response(status_code=400, detail='key by reference not implemented')

            if unverified_grant_req.client.key.jwk is not None:
                client_key = jws.JWK(**unverified_grant_req.client.key.jwk.dict(exclude_unset=True))

            # Verify jws
            if client_key is not None:
                try:
                    jwstoken.verify(client_key)
                    logger.info('JWS token verified')
                except jws.InvalidJWSSignature as e:
                    logger.error(f'JWS signature failure: {e}')
                    return return_error_response(status_code=400, detail='JWS signature could not be verified')
            else:
                return return_error_response(status_code=400, detail='no client key found')

            # JWS verified, replace body with deserialized token
            request.context.jws_verified = True
            try:
                request.context.jws_headers = JWSHeaders(**jwstoken.jose_header)
            except ValidationError as e:
                logger.error('Missing JWS header')
                return return_error_response(status_code=400, detail=str(e))
            await set_body(request, jwstoken.payload)

        return await call_next(request)
