# -*- coding: utf-8 -*-
import logging

from jwcrypto import jws
from jwcrypto.common import JWException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Message

from auth_server.context import ContextRequestMixin

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
        if request.headers.get('content-type') == 'application/jose':
            # Return a more helpful error message for a common mistake
            return return_error_response(status_code=422, detail='content-type needs to be application/jose+json')

        if request.headers.get('content-type') == 'application/jose+json':
            request = self.make_context_request(request)
            logger.info('got application/jose request')
            body = await get_body(request)
            # deserialize jws
            body_str = body.decode("utf-8")
            logger.debug(f'body: {body_str}')
            jwstoken = jws.JWS()
            try:
                jwstoken.deserialize(body_str)
            except JWException:
                logger.exception('JWS deserialization failure')
                return return_error_response(status_code=400, detail='JWS could not be deserialized')
            logger.info('JWS token deserialized')
            logger.debug(f'JWS: {jwstoken.objects}')

            # add jws to context request to be verified later
            request.context.jws_obj = jwstoken
            # replace body with unverified deserialized token - verification is done when verifying proof
            await set_body(request, jwstoken.objects['payload'])

        return await call_next(request)
