# -*- coding: utf-8 -*-

from typing import Callable, Optional, Union

from fastapi import Request, Response
from fastapi.routing import APIRoute
from jwcrypto import jws
from pydantic import BaseModel, ConfigDict

__author__ = "lundberg"


class Context(BaseModel):
    jws_verified: bool = False
    client_cert: Optional[str] = None
    jws_obj: Optional[jws.JWS] = None
    detached_jws: Optional[str] = None
    detached_jws_body: Optional[str] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def to_dict(self):
        return self.dict()


class ContextRequest(Request):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def context(self):
        try:
            context = self.state.context
            if isinstance(context, dict):
                self.state.context = Context(**context)
        except AttributeError:
            # Lazy init of self.state.context
            self.state.context = Context()
        return self.state.context

    @context.setter
    def context(self, context: Context):
        self.state.context = context


class ContextRequestMixin:
    @staticmethod
    def make_context_request(request: Union[Request, ContextRequest]) -> ContextRequest:
        if not isinstance(request, ContextRequest):
            request = ContextRequest(request.scope, request.receive)
        return request


class ContextRequestRoute(APIRoute, ContextRequestMixin):
    """
    Make ContextRequest the default request class
    """

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def context_route_handler(request: Union[Request, ContextRequest]) -> Response:
            request = self.make_context_request(request)
            return await original_route_handler(request)

        return context_route_handler
