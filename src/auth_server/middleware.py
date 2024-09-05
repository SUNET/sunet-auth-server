# -*- coding: utf-8 -*-
import logging
from typing import Any, Optional

from jwcrypto import jws
from jwcrypto.common import JWException
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth_server.context import Context

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def get_header_index(scope: Scope, header_key: bytes) -> Optional[int]:
    for key, value in scope["headers"]:
        if key == header_key:
            return scope["headers"].index((key, value))
    return None


def set_header(scope: Scope, header: tuple[bytes, bytes]) -> None:
    content_type_index = get_header_index(scope, header[0])
    if content_type_index:
        logger.debug(f"Replacing header {scope['headers'][content_type_index]} with {header}")
        scope["headers"][content_type_index] = header
    else:
        # no header to replace, just set it
        scope["headers"].append(header)


def set_context(scope: Scope, data: dict[str, Any]) -> None:
    context = scope["state"].get("context")
    if not context:
        context = Context().to_dict()
    context.update(data)
    scope["state"]["context"] = context


# see https://github.com/florimondmanca/msgpack-asgi for a good example
class JOSEMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            preparer = JOSEPreparer(self.app)
            await preparer(scope, receive, send)
            return
        await self.app(scope, receive, send)


class JOSEPreparer:
    def __init__(self, app) -> None:
        self.app: ASGIApp = app
        self.is_jose: bool = False
        self.is_detached_jws: bool = False
        self.receive: Receive = unattached_receive
        self.send: Send = unattached_send

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers: dict[bytes, bytes] = dict(scope["headers"])
        acceptable_jose_content_types = [b"application/jose", b"application/jose+json"]
        self.is_jose = headers.get(b"content-type") in acceptable_jose_content_types
        self.is_detached_jws = headers.get(b"detached-jws") is not None

        self.receive = receive
        self.send = send

        async def receive_jose() -> Message:
            message = await self.receive()

            if message["type"] != "http.request":
                return message

            if not self.is_jose and not self.is_detached_jws:
                return message

            body = message["body"]
            more_body = message.get("more_body", False)
            if more_body:
                # Some implementations (e.g. HTTPX) may send one more empty-body message.
                # Make sure they don't send one that contains a body, or it means
                # that clients attempt to stream the request body.
                message = await self.receive()
                if message["body"] != b"":
                    raise HTTPException(status_code=400, detail="Streaming the request body isn't supported yet")

            body_str = body.decode("utf-8")

            if self.is_detached_jws:
                # add original body to context for later use
                logger.debug(f"detached JWS body: {body_str}")
                set_context(scope, data={"detached_jws_body": body_str})
                logger.info("added detached JWS original body to request state")
            elif self.is_jose:
                # deserialize jws and replace body with the resulting json
                logger.debug(f"JWS body: {body_str}")
                jwstoken = jws.JWS()
                try:
                    jwstoken.deserialize(body_str)
                except JWException:
                    logger.exception("JWS deserialization failure")
                    raise HTTPException(status_code=400, detail="JWS could not be deserialized")
                logger.info("JWS token deserialized")
                logger.debug(f"JWS: {jwstoken.objects}")

                # add jws to context request to be verified later
                set_context(scope, data={"jws_obj": jwstoken})
                # replace body with unverified deserialized token - verification is done later in proof.jws
                message["body"] = jwstoken.objects["payload"]
                # set content-type to application/json as the body has changed
                set_header(scope, (b"content-type", b"application/json"))
                # update content-length header to match the new body
                content_length = str(len(jwstoken.objects["payload"]))
                set_header(scope, (b"content-length", content_length.encode("utf-8")))
            return message

        await self.app(scope, receive_jose, send)


async def unattached_receive() -> Message:
    raise RuntimeError("receive awaitable not set")


async def unattached_send(message: Message) -> None:
    raise RuntimeError("send awaitable not set")
