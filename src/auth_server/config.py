import json
import os
from datetime import timedelta
from enum import StrEnum
from functools import lru_cache
from os import environ
from pathlib import Path
from sys import stderr
from typing import Any, Self

import yaml
from pydantic import AnyUrl, BaseModel, Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from auth_server.models.gnap import Proof
from auth_server.models.jose import ECJWK, OKPJWK, RSAJWK, SymmetricJWK

__author__ = "lundberg"


class ConfigurationError(Exception):
    pass


class Environment(StrEnum):
    DEV = "dev"
    PROD = "prod"


class LoggingFilters(StrEnum):
    """Identifiers to coherently map elements in LocalContext.filters to filter classes in logging dictConfig."""

    DEBUG_TRUE = "require_debug_true"
    DEBUG_FALSE = "require_debug_false"


class FlowName(StrEnum):
    CAFLOW = "CAFlow"
    CONFIGFLOW = "ConfigFlow"
    INTERACTIONFLOW = "InteractionFlow"
    MDQFLOW = "MDQFlow"
    TESTFLOW = "TestFlow"
    TLSFEDFLOW = "TLSFEDFlow"


class ClientKey(BaseModel):
    proof: Proof
    jwk: OKPJWK | ECJWK | RSAJWK | SymmetricJWK | None = None
    cert: str | None = None
    cert_S256: str | None = None
    claims: dict[str, Any] = {}


class TLSFEDMetadata(BaseModel):
    remote: AnyUrl | None = None
    local: Path | None = None
    jwks: Path
    strict: bool = True  # set to False to load partial metadata on entity errors


class AuthServerConfig(BaseSettings):
    app_name: str = Field(default="auth-server")
    environment: Environment = Field(default=Environment.PROD)
    debug: bool = False
    testing: bool = False
    log_format: str | None = None
    log_level: str = "INFO"
    log_filters: list[LoggingFilters] = Field(default_factory=list)
    log_queue_size: int = Field(default=10000, gt=0)
    logging_config: dict = Field(default_factory=dict)
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080)
    application_root: str = Field(default="")
    auth_flows: list[str] = Field(default_factory=list)
    mdq_server: str | None = Field(default=None)
    tls_fed_metadata: list[TLSFEDMetadata] = Field(default_factory=list)
    tls_fed_metadata_cache_ttl: timedelta = Field(default=timedelta(hours=1), gt=timedelta(0))
    tls_fed_metadata_retry_interval: timedelta = Field(default=timedelta(minutes=1), gt=timedelta(0))
    # how long metadata may be served after renew_at while refreshes are failing
    tls_fed_metadata_stale_grace: timedelta = Field(default=timedelta(minutes=5), gt=timedelta(0))
    keystore_path: Path = Field(default=Path("keystore.jwks"))
    signing_key_id: str = Field(default="default")
    auth_token_issuer: str
    auth_token_audience: str | None = Field(default=None)
    auth_token_expires_in: timedelta = Field(default=timedelta(hours=10))
    http_client_timeout: timedelta = Field(default=timedelta(seconds=10), gt=timedelta(0))
    proof_jws_max_age: timedelta = Field(default=timedelta(minutes=5))
    proof_httpsig_max_age: timedelta = Field(default=timedelta(minutes=5))
    proof_httpsig_clock_skew: timedelta = Field(default=timedelta(seconds=30))
    # Public base URL (scheme and authority) clients sign for httpsig and jws proofs, set when running behind a
    # proxy that rewrites scheme, host or port. Never derived from forwarded headers.
    proof_external_base_url: AnyUrl | None = None
    proof_httpsig_require_content_type: bool = False  # require content-type to be signed when there is a body
    # require a signed nonce in every httpsig signature, without one a request can be replayed until max age expires
    proof_httpsig_nonce_required: bool = True
    client_keys: dict[str, ClientKey] = Field(default_factory=dict)
    mongo_uri: str | None = None
    transaction_state_expires_in: timedelta = Field(default=timedelta(minutes=10))
    pysaml2_config_path: Path | None = Field(default=None)
    pysaml2_config_name: str = "SAML_CONFIG"
    saml2_discovery_service_url: AnyUrl | None = None
    saml2_single_idp: str | None = None
    ca_certs_path: Path | None = None  # all files ending with .c* will be loaded recursively. PEM and DER supported
    ca_certs_mandatory_org_id: bool = False  # fail grant requests where no org id is found in the certificate

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls: type["AuthServerConfig"], v: str) -> str:
        if v.endswith("/"):
            v = v.removesuffix("/")
        return v

    @field_validator("proof_external_base_url")
    @classmethod
    def proof_external_base_url_must_be_origin(cls: type["AuthServerConfig"], v: AnyUrl | None) -> AnyUrl | None:
        if v is None:
            return v
        if v.scheme not in ("http", "https"):
            raise ValueError("proof_external_base_url must be an http or https url")
        if v.username or v.password or v.query or v.fragment or v.path not in (None, "", "/"):
            raise ValueError("proof_external_base_url must only contain scheme, host and port")
        return v

    @model_validator(mode="after")
    def stale_grace_must_cover_retry_interval(self: Self) -> Self:
        if self.tls_fed_metadata_stale_grace < self.tls_fed_metadata_retry_interval:
            raise ValueError(
                "tls_fed_metadata_stale_grace must be greater than or equal to tls_fed_metadata_retry_interval"
            )
        return self

    model_config = SettingsConfigDict(frozen=True)


def read_config_file(config_file: str, config_ns: str = "") -> dict:
    with open(config_file) as f:
        data = yaml.safe_load(f)
    # traverse the loaded data to the right namespace, discarding everything else
    for this in config_ns.split("/"):
        if not this:
            continue
        data = data[this]
    return data


@lru_cache
def load_config() -> AuthServerConfig:
    try:
        config_file = environ.get("config_file")
        if config_file is not None:
            config_ns = environ.get("config_ns", "")
            data = read_config_file(config_file=config_file, config_ns=config_ns)
            config = AuthServerConfig.parse_obj(data)
        else:
            # config will be instantiated with env vars if there is no config file
            config = AuthServerConfig()
        # Save config to a file in /dev/shm for introspection
        fd_int = os.open(f"/dev/shm/{config.app_name}_config.yaml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd_int, "w") as fd:
            fd.write("---\n")
            # have to take the detour over json to get things like enums serialised to strings
            yaml.safe_dump(json.loads(config.json()), fd)
        return config
    except ValidationError as e:
        stderr.write(f"Configuration error: {e}")
        stderr.write("Configuration schema:")
        stderr.write(AuthServerConfig.schema_json(indent=2))
        raise ConfigurationError(f"{e}")
