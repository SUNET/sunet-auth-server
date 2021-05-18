# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import timedelta
from enum import Enum
from functools import lru_cache
from os import environ
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import AnyUrl, BaseModel, BaseSettings, Field

from auth_server.models.gnap import Proof
from auth_server.models.jose import ECJWK, RSAJWK, SymmetricJWK

__author__ = 'lundberg'


class ConfigurationError(Exception):
    pass


class Environment(str, Enum):
    DEV = 'dev'
    PROD = 'prod'


class ClientKey(BaseModel):
    proof: Proof
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]] = None
    cert: Optional[str] = None
    cert_S256: Optional[str] = None
    claims: Dict[str, Any] = {}


class TLSFEDMetadata(BaseModel):
    remote: Optional[AnyUrl] = None
    local: Optional[Path] = None
    jwks: Path


class AuthServerConfig(BaseSettings):
    app_name: str = Field(default='auth-server', env='APP_NAME')
    environment: Environment = Field(default=Environment.PROD, env='ENVIRONMENT')
    testing: bool = False
    log_level: str = Field(default='INFO', env='LOG_LEVEL')
    host: str = Field(default='0.0.0.0', env='HOST')
    port: int = Field(default=3000, env='PORT')
    auth_flows: List[str] = Field(default=['FullFlow'], env='AUTH_FLOWS')
    base_url: str = Field(default='', env='BASE_URL')
    mdq_server: Optional[str] = Field(default=None, env='MDQ_SERVER')
    tls_fed_metadata: List[TLSFEDMetadata] = Field(default=[], env='TLS_FED_METADATA')
    tls_fed_metadata_max_age: timedelta = Field(default='PT1H', env='TLS_FED_METADATA_MAX_AGE')
    keystore_path: Path = Field(default='keystore.jwks', env='KEYSTORE')
    auth_token_issuer: str = Field(default='', env='AUTH_TOKEN_ISSUER')
    auth_token_audience: str = Field(default='', env='AUTH_TOKEN_AUDIENCE')
    auth_token_expires_in: timedelta = Field(default='P10D', env='AUTH_TOKEN_EXPIRES_IN')
    proof_jws_max_age: timedelta = Field(default='PT5M', env='PROOF_JWS_MAX_AGE')
    client_keys: Dict[str, ClientKey] = Field(default={}, env='CLIENT_KEYS')

    class Config:
        frozen = True  # make hashable


def read_config_file(config_file: str, config_path: str = '') -> Dict:
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
    # traverse the loaded data to the right namespace, discarding everything else
    for this in config_path.split('/'):
        if not this:
            continue
        data = data[this]
    return data


@lru_cache
def load_config() -> AuthServerConfig:
    config_file = environ.get('CONFIG_FILE')
    if config_file is not None:
        config_path = environ.get('CONFIG_PATH', '')
        data = read_config_file(config_file=config_file, config_path=config_path)
        return AuthServerConfig.parse_obj(data)
    return AuthServerConfig()
