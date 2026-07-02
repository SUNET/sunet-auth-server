import logging
from typing import Self, cast

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.staticfiles import StaticFiles

from auth_server.config import AuthServerConfig, ConfigurationError, FlowName, load_config
from auth_server.context import ContextRequestRoute
from auth_server.errors import GNAPErrorException
from auth_server.flows import BaseAuthFlow, CAFlow, ConfigFlow, InteractionFlow, MDQFlow, TestFlow, TLSFEDFlow
from auth_server.logging import init_logging
from auth_server.middleware import JOSEMiddleware
from auth_server.models.gnap import ErrorCode, GNAPErrorDetail, GrantResponse
from auth_server.routers.interaction import interaction_router
from auth_server.routers.root import root_router
from auth_server.routers.saml2_sp import saml2_router
from auth_server.routers.status import status_router
from auth_server.utils import import_class

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class AuthServer(FastAPI):
    def __init__(self: Self) -> None:
        config = load_config()
        super().__init__(root_path=config.application_root)
        init_logging(config=config)

        # Load flows
        self.builtin_flow: dict[FlowName, type[BaseAuthFlow]] = {
            FlowName.CAFLOW: CAFlow,
            FlowName.CONFIGFLOW: ConfigFlow,
            FlowName.INTERACTIONFLOW: InteractionFlow,
            FlowName.MDQFLOW: MDQFlow,
            FlowName.TESTFLOW: TestFlow,
            FlowName.TLSFEDFLOW: TLSFEDFlow,
        }
        self.auth_flows = self.load_flows(config=config)

    def load_flows(self: Self, config: AuthServerConfig) -> dict[str, type[BaseAuthFlow]]:
        flows: dict[str, type[BaseAuthFlow]] = {}
        for flow in config.auth_flows:
            try:
                builtin_flow = self.builtin_flow.get(FlowName(flow))
                if builtin_flow:
                    flows[builtin_flow.get_name()] = builtin_flow
                    logger.debug(f"Loaded built-in flow {flow}")
            except ValueError:  # Not a registered flow
                try:
                    custom_flow = cast(type[BaseAuthFlow], import_class(flow))
                    custom_flow_name = custom_flow.get_name()
                    if custom_flow_name in flows:
                        # reject a custom flow that tries to overwrite another flow
                        raise ConfigurationError(f"there is already a flow named {custom_flow_name} loaded")
                    flows[custom_flow_name] = custom_flow
                    logger.debug(f"Loaded custom flow {flow}")
                except (ValueError, ModuleNotFoundError) as e:
                    logger.error(f"Could not load custom flow {flow}: {e}")
        logger.info(f"Loaded flows: {[flow.get_name() for flow in flows.values()]}")
        return flows


def init_auth_server_api() -> AuthServer:
    app = AuthServer()
    app.router.route_class = ContextRequestRoute
    app.add_middleware(JOSEMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(root_router)
    app.include_router(interaction_router)
    app.include_router(saml2_router)
    app.include_router(status_router)
    app.mount(
        "/static", StaticFiles(packages=["auth_server"]), name="static"
    )  # defaults to the "statics" directory (the ending s is not a mistake) because starlette says so

    @app.exception_handler(GNAPErrorException)
    async def gnap_error_handler(request: Request, exc: GNAPErrorException) -> JSONResponse:
        error = GrantResponse(error=GNAPErrorDetail(code=exc.error_code, description=exc.description))
        return JSONResponse(
            content=error.model_dump(exclude_none=True, by_alias=True),
            status_code=exc.status_code,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
        logger.info(f"validation error for {request.url.path}: {exc_str}")
        error = GrantResponse(error=GNAPErrorDetail(code=ErrorCode.INVALID_REQUEST, description=exc_str))
        return JSONResponse(
            content=error.model_dump(exclude_none=True, by_alias=True),
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )

    return app
