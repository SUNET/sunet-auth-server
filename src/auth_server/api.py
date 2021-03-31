# -*- coding: utf-8 -*-
import logging
from typing import Any, Mapping, Optional

from fastapi import Depends, FastAPI

from auth_server.config import AuthServerConfig, load_config
from auth_server.log import init_logging
from auth_server.routers.root import root_router
from auth_server.utils import load_jwks

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


class AuthServer(FastAPI):
    def __init__(self):
        super().__init__()
        config = load_config()
        init_logging(level=config.log_level)


def init_auth_server_api() -> AuthServer:
    app = AuthServer()
    app.include_router(root_router)
    return app
