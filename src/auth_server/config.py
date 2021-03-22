# -*- coding: utf-8 -*-

from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from pydantic import BaseSettings, Field

__author__ = 'lundberg'


class Environment(str, Enum):
    DEV = 'dev'
    PROD = 'prod'


class AuthServerConfig(BaseSettings):
    app_name: str = Field(default='auth-server', env='APP_NAME')
    environment: Environment = Field(default=Environment.PROD, env='ENVIRONMENT')
    testing: bool = False
    host: str = Field(default='0.0.0.0', env='HOST')
    port: int = Field(default=3000, env='PORT')
    base_url: str = Field(default='', env='BASE_URL')
    mdq_server: str = Field(env='MDQ_SERVER')
    keystore_path: Path = Field(default='keystore.jwks', env='KEYSTORE')
    audience: str = Field(env='AUDIENCE')
    expires_in: timedelta = Field(default='P10D', env='EXPIRES_IN')
    log_level: str = Field(default='INFO', env='LOG_LEVEL')
    test_mode: bool = Field(
        default=False, env='TEST_MODE'
    )  # This is dangerous and turns off security - only for debugging


def load_config(test_config: Optional[Mapping[str, Any]] = None) -> AuthServerConfig:
    if test_config:
        return AuthServerConfig(**test_config)
    return AuthServerConfig()
