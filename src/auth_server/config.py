# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import timedelta
from enum import Enum
from functools import lru_cache
from os import environ
from pathlib import Path
from sys import stderr
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import AnyUrl, BaseModel, BaseSettings, Field, ValidationError

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
    app_name: str = Field(default='auth-server')
    environment: Environment = Field(default=Environment.PROD)
    testing: bool = False
    log_level: str = Field(default='INFO')
    host: str = Field(default='0.0.0.0')
    port: int = Field(default=8080)
    base_url: str = Field(default='')
    auth_flows: List[str] = Field(default=['FullFlow'])
    mdq_server: Optional[str] = Field(default=None)
    tls_fed_metadata: List[TLSFEDMetadata] = Field(default=[])
    tls_fed_metadata_max_age: timedelta = Field(default='PT1H')
    keystore_path: Path = Field(default='keystore.jwks')
    auth_token_issuer: str = Field(default='')
    auth_token_audience: str = Field(default='')
    auth_token_expires_in: timedelta = Field(default='P10D')
    proof_jws_max_age: timedelta = Field(default='PT5M')
    client_keys: Dict[str, ClientKey] = Field(default={})

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
    try:
        config_file = environ.get('config_file')
        if config_file is not None:
            config_path = environ.get('config_path', '')
            data = read_config_file(config_file=config_file, config_path=config_path)
            return AuthServerConfig.parse_obj(data)
        return AuthServerConfig()
    except ValidationError as e:
        stderr.write(f'Configuration error: {e}')
        stderr.write('Configuration schema:')
        stderr.write(AuthServerConfig.schema_json(indent=2))
        raise ConfigurationError(f'{e}')
