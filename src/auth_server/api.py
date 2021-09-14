# -*- coding: utf-8 -*-
import logging
from typing import List, Type, cast

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from auth_server.config import AuthServerConfig, load_config
from auth_server.context import ContextRequestRoute
from auth_server.flows import BaseAuthFlow, BuiltInFlow, ConfigFlow, FullFlow, MDQFlow, TestFlow, TLSFEDFlow
from auth_server.log import init_logging
from auth_server.middleware import JOSEMiddleware
from auth_server.routers.interaction import interaction_router
from auth_server.routers.root import root_router
from auth_server.routers.status import status_router
from auth_server.utils import import_class

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


class AuthServer(FastAPI):
    def __init__(self):
        super().__init__()
        config = load_config()
        init_logging(level=config.log_level)

        # Load flows
        self.auth_flows = self.load_flows(config=config)

    @staticmethod
    def load_flows(config: AuthServerConfig) -> List[Type[BaseAuthFlow]]:
        flows: List[Type[BaseAuthFlow]] = []
        for flow in config.auth_flows:
            try:
                builtin_flow = BuiltInFlow(flow)
                if builtin_flow is BuiltInFlow.FULLFLOW:
                    flows.append(FullFlow)
                elif builtin_flow is BuiltInFlow.MDQFLOW:
                    flows.append(MDQFlow)
                elif builtin_flow is BuiltInFlow.TLSFEDFLOW:
                    flows.append(TLSFEDFlow)
                elif builtin_flow is BuiltInFlow.CONFIGFLOW:
                    flows.append(ConfigFlow)
                elif builtin_flow is BuiltInFlow.TESTFLOW:
                    flows.append(TestFlow)
                logger.debug(f'Loaded built-in flow {flow}')
            except ValueError:  # Not a built in flow
                try:
                    custom_flow = cast(Type[BaseAuthFlow], import_class(flow))
                    flows.append(custom_flow)
                    logger.debug(f'Loaded custom flow {flow}')
                except (ValueError, ModuleNotFoundError) as e:
                    logger.error(f'Could not load custom flow {flow}: {e}')
        logger.info(f'Loaded flows: {[flow.get_name() for flow in flows]}')
        return flows


def init_auth_server_api() -> AuthServer:
    app = AuthServer()
    app.router.route_class = ContextRequestRoute
    app.add_middleware(JOSEMiddleware)
    app.include_router(root_router)
    app.include_router(interaction_router)
    app.include_router(status_router)
    app.mount("/static", StaticFiles(packages=['auth_server']), name="static")  # defaults to the "statics" directory
    return app
