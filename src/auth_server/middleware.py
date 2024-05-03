# -*- coding: utf-8 -*-
from typing import Optional

from jwcrypto import jws
from jwcrypto.common import JWException
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Message

from auth_server.context import ContextRequestMixin

__author__ = "lundberg"


# middleware needs to return a reponse
# some background: https://github.com/tiangolo/fastapi/issues/458
def return_error_response(status_code: int, detail: str):
    return PlainTextResponse(status_code=status_code, content=detail)


# Hack to be able to get request body both now and later
# https://github.com/encode/starlette/issues/495#issuecomment-513138055
async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


def get_header_index(request: Request, header_key: bytes) -> Optional[int]:
    for key, value in request.scope["headers"]:
        if key == header_key:
            return request.scope["headers"].index((key, value))
    return None


def set_header(request: Request, header_key: str, header_value: str) -> None:
    b_header_key = header_key.encode("utf-8")
    b_header_value = header_value.encode("utf-8")
    content_type_index = get_header_index(request, b_header_key)
    if content_type_index:
        logger.debug(
            f"Replacing header {request.scope['headers'][content_type_index]} with {(b_header_key, b_header_value)}"
        )
        request.scope["headers"][content_type_index] = (b_header_key, b_header_value)
    else:
        # no header to replace, just set it
        request.scope["headers"].append((b_header_key, b_header_value))


class JOSEMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        acceptable_jose_content_types = ["application/jose", "application/jose+json"]
        is_jose = request.headers.get("content-type") in acceptable_jose_content_types
        is_detached_jws = request.headers.get("Detached-JWS") is not None

        if is_jose and not is_detached_jws:
            request = self.make_context_request(request)
            logger.info("got application/jose+json request")
            body = await get_body(request)
            # deserialize jws
            body_str = body.decode("utf-8")
            logger.debug(f"JWS body: {body_str}")
            jwstoken = jws.JWS()
            try:
                jwstoken.deserialize(body_str)
            except JWException:
                logger.exception("JWS deserialization failure")
                return return_error_response(status_code=400, detail="JWS could not be deserialized")
            logger.info("JWS token deserialized")
            logger.debug(f"JWS: {jwstoken.objects}")

            # add jws to context request to be verified later
            request.context.jws_obj = jwstoken
            # replace body with unverified deserialized token - verification is done when verifying proof
            await set_body(request, jwstoken.objects["payload"])
            # set content-type to application/json as the body has changed
            set_header(request, "content-type", "application/json")
            # update content-length header to match the new body
            set_header(request, "content-length", str(len(jwstoken.objects["payload"])))

        if is_detached_jws:
            request = self.make_context_request(request)
            logger.info("got detached jws request")
            # save original body for the detached jws validation
            body = await get_body(request)
            body_str = body.decode("utf-8")
            logger.debug(f"JWSD body: {body_str}")
            request.context.detached_jws_body = body_str

        return await call_next(request)
