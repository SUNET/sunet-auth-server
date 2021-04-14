# -*- coding: utf-8 -*-
from __future__ import annotations

import typing
from datetime import timedelta
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Union

from pydantic import BaseSettings, Field

if typing.TYPE_CHECKING:  # Avoid circular dependencies
    from auth_server.models.gnap import Proof
    from auth_server.models.jose import ECJWK, RSAJWK, SymmetricJWK

__author__ = 'lundberg'


class Environment(str, Enum):
    DEV = 'dev'
    PROD = 'prod'


class ClientKey(BaseSettings):
    proof: Proof
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]] = None
    cert: Optional[str] = None
    cert_S256: Optional[str] = None
    # TODO: Figure out other data to add here to help with access token creation


class AuthServerConfig(BaseSettings):
    app_name: str = Field(default='auth-server', env='APP_NAME')
    environment: Environment = Field(default=Environment.PROD, env='ENVIRONMENT')
    testing: bool = False
    log_level: str = Field(default='INFO', env='LOG_LEVEL')
    host: str = Field(default='0.0.0.0', env='HOST')
    port: int = Field(default=3000, env='PORT')
    base_url: str = Field(default='', env='BASE_URL')
    mdq_server: Optional[str] = Field(default=None, env='MDQ_SERVER')
    keystore_path: Path = Field(default='keystore.jwks', env='KEYSTORE')
    auth_token_audience: str = Field(default='', env='AUTH_TOKEN_AUDIENCE')
    auth_token_expires_in: timedelta = Field(default='P10D', env='AUTH_TOKEN_EXPIRES_IN')
    jws_max_age: timedelta = Field(default='PT5M', env='JWS_MAX_AGE')
    client_keys: Dict[str, ClientKey] = Field(default={}, env='CLIENT_KEYS')
    test_mode: bool = Field(
        default=False, env='TEST_MODE'
    )  # This is dangerous and turns off security - only for debugging

    class Config:
        frozen = True  # make hashable


@lru_cache
def load_config() -> AuthServerConfig:
    # TODO: Implement config loading from yaml file
    return AuthServerConfig()
