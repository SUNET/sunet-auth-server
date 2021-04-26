# -*- coding: utf-8 -*-
import logging
from typing import Type, cast

from fastapi import FastAPI

from auth_server.config import load_config
from auth_server.context import ContextRequestRoute
from auth_server.flows import BaseAuthFlow
from auth_server.log import init_logging
from auth_server.middleware import JOSEMiddleware
from auth_server.routers.root import root_router
from auth_server.utils import import_class

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


class AuthServer(FastAPI):
    def __init__(self):
        super().__init__()
        config = load_config()
        init_logging(level=config.log_level)
        self.auth_flow_class: Type[BaseAuthFlow] = cast(Type[BaseAuthFlow], import_class(config.auth_flow_class))


def init_auth_server_api() -> AuthServer:
    app = AuthServer()
    app.router.route_class = ContextRequestRoute
    app.add_middleware(JOSEMiddleware)
    app.include_router(root_router)
    return app
