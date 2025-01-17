from collections.abc import Callable
from typing import Any, Self

from fastapi import Request, Response
from fastapi.routing import APIRoute
from jwcrypto import jws
from pydantic import BaseModel, ConfigDict

__author__ = "lundberg"

from starlette.requests import empty_receive, empty_send
from starlette.types import Receive, Scope, Send


class Context(BaseModel):
    jws_verified: bool = False
    client_cert: str | None = None
    jws_obj: jws.JWS | None = None
    detached_jws: str | None = None
    detached_jws_body: str | None = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def to_dict(self: Self) -> dict[str, Any]:
        return self.model_dump()


class ContextRequest(Request):
    def __init__(self: Self, scope: Scope, receive: Receive = empty_receive, send: Send = empty_send) -> None:
        super().__init__(scope=scope, receive=receive, send=send)

    @property
    def context(self: Self) -> Context:
        try:
            context = self.state.context
            if isinstance(context, dict):
                self.state.context = Context(**context)
        except AttributeError:
            # Lazy init of self.state.context
            self.state.context = Context()
        return self.state.context

    @context.setter
    def context(self: Self, context: Context) -> None:
        self.state.context = context


class ContextRequestMixin:
    @staticmethod
    def make_context_request(request: Request | ContextRequest) -> ContextRequest:
        if not isinstance(request, ContextRequest):
            request = ContextRequest(request.scope, request.receive)
        return request


class ContextRequestRoute(APIRoute, ContextRequestMixin):
    """
    Make ContextRequest the default request class
    """

    def get_route_handler(self: Self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def context_route_handler(request: Request | ContextRequest) -> Response:
            request = self.make_context_request(request)
            return await original_route_handler(request)

        return context_route_handler
