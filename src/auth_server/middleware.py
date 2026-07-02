import logging
from typing import Any, Self

from jwcrypto import jws
from jwcrypto.common import JWException
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from auth_server.context import Context
from auth_server.models.gnap import ErrorCode, GNAPErrorDetail, GrantResponse

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def get_header_index(scope: Scope, header_key: bytes) -> int | None:
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
    def __init__(self: Self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self: Self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            preparer = JOSEPreparer(self.app)
            await preparer(scope, receive, send)
            return
        await self.app(scope, receive, send)


class JOSEPreparer:
    def __init__(self: Self, app: ASGIApp) -> None:
        self.app: ASGIApp = app
        self.is_jose: bool = False
        self.is_detached_jws: bool = False
        self.receive: Receive = unattached_receive
        self.send: Send = unattached_send

    async def __call__(self: Self, scope: Scope, receive: Receive, send: Send) -> None:
        headers: dict[bytes, bytes] = dict(scope["headers"])
        acceptable_jose_content_types = [b"application/jose", b"application/jose+json"]
        self.is_jose = headers.get(b"content-type") in acceptable_jose_content_types
        self.is_detached_jws = headers.get(b"detached-jws") is not None

        self.receive = receive
        self.send = send

        buffered_message: Message | None = None
        if self.is_jose:
            # Deserialize the JWS eagerly, before handing off to the wrapped app. Doing this lazily from
            # within receive_jose below means FastAPI's body-parsing guard (fastapi.routing) rewraps any
            # non-HTTPException raised while reading the body into a generic HTTPException with the legacy
            # {"detail": ...} shape. By the time that propagates back out here, Starlette's
            # ExceptionMiddleware (which sits *inside* this middleware in the stack) has already turned it
            # into a response, so we'd never get a chance to produce a proper RFC 9635 error response.
            # Validating eagerly, before self.app is invoked at all, avoids that.
            message = await self.receive()
            error_response = await self._prepare_jose_message(scope, message)
            if error_response is not None:
                await error_response(scope, receive, send)
                return
            buffered_message = message

        async def receive_jose() -> Message:
            nonlocal buffered_message
            if buffered_message is not None:
                message, buffered_message = buffered_message, None
                return message

            message = await self.receive()

            if message["type"] != "http.request" or not self.is_detached_jws:
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

            # add original body to context for later use
            logger.debug(f"detached JWS body: {body_str}")
            set_context(scope, data={"detached_jws_body": body_str})
            logger.info("added detached JWS original body to request state")
            return message

        await self.app(scope, receive_jose, send)

    async def _prepare_jose_message(self: Self, scope: Scope, message: Message) -> JSONResponse | None:
        """Deserialize an application/jose(+json) body and update message/scope in place.

        Returns a JSONResponse describing the error if deserialization failed, or None on success.
        """
        if message["type"] != "http.request":
            return None

        body = message["body"]
        more_body = message.get("more_body", False)
        if more_body:
            # Some implementations (e.g. HTTPX) may send one more empty-body message.
            # Make sure they don't send one that contains a body, or it means
            # that clients attempt to stream the request body.
            next_message = await self.receive()
            if next_message["body"] != b"":
                raise HTTPException(status_code=400, detail="Streaming the request body isn't supported yet")

        body_str = body.decode("utf-8")

        # deserialize jws and replace body with the resulting json
        logger.debug(f"JWS body: {body_str}")
        jwstoken = jws.JWS()
        try:
            jwstoken.deserialize(body_str)
        except JWException:
            logger.exception("JWS deserialization failure")
            error = GrantResponse(
                error=GNAPErrorDetail(code=ErrorCode.INVALID_CLIENT, description="JWS could not be deserialized")
            )
            return JSONResponse(
                content=error.model_dump(exclude_none=True, by_alias=True),
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
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
        return None


async def unattached_receive() -> Message:
    raise RuntimeError("receive awaitable not set")


async def unattached_send(message: Message) -> None:
    raise RuntimeError("send awaitable not set")
