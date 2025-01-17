import logging
import logging.config
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pprint import pformat
from typing import Any, Self

from auth_server.config import AuthServerConfig, ConfigurationError, LoggingFilters

__author__ = "lundberg"


DEFAULT_FORMAT = "{asctime} | {levelname:7} | {name:35} | {module:10} | {message}"


# Default to RFC3339/ISO 8601 with tz
class CustomFormatter(logging.Formatter):
    def __init__(self: Self, relative_time: bool = False, fmt: str | None = None) -> None:
        super().__init__(fmt=fmt, style="{")
        self._relative_time = relative_time

    def formatTime(self: Self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        if self._relative_time:
            # Relative time makes much more sense than absolute time when running tests for example
            _seconds = record.relativeCreated / 1000
            return f"{_seconds:.3f}s"

        # self.converter seems incorrectly typed as a two-argument method (Callable[[Optional[float]], struct_time])
        ct = self.converter(record.created)
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%dT%H:%M:%S", ct)
            tz = time.strftime("%z", ct)  # Can evaluate to empty string
            if tz:
                tz = f"{tz[:3]}:{tz[3:]}"  # Need colon to follow the rfc/iso
            s = f"{t}.{record.msecs:03.0f}{tz}"
        return s


class RequireDebugTrue(logging.Filter):
    """A filter to discard log records if config.debug is not True. Generally not used."""

    def __init__(self: Self, app_debug: bool) -> None:
        super().__init__()
        self.app_debug = app_debug

    def filter(self: Self, record: logging.LogRecord) -> bool:
        return self.app_debug


class RequireDebugFalse(logging.Filter):
    """A filter to discard log records if config.debug is not False. Generally not used."""

    def __init__(self: Self, app_debug: bool) -> None:
        super().__init__()
        self.app_debug = app_debug

    def filter(self: Self, record: logging.LogRecord) -> bool:
        return not self.app_debug


def merge_config(base_config: dict[str, Any], new_config: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two dictConfig dicts."""

    def merge(node: dict[str, Any], key: str, value: object) -> None:
        if isinstance(value, dict):
            for item in value:
                try:
                    merge(node[key], item, value[item])
                except KeyError:
                    # No such key in base_config, just set it
                    node[key] = value
        else:
            node[key] = value

    for k, v in new_config.items():
        merge(base_config, k, v)
    return base_config


def init_logging(config: AuthServerConfig) -> None:
    """
    Init logging in a Flask app using dictConfig.

    See `make_local_context` for how to configure logging.

    Merges optional dictConfig from settings before initializing (config key 'logging_config').
    """
    local_context = make_local_context(config)
    logging_config = make_dictConfig(local_context)

    logging_config = merge_config(logging_config, config.logging_config)

    logging.config.dictConfig(logging_config)
    if config.debug:
        logging.debug(f"Logging config:\n{pformat(logging_config)}")
    logging.info("Logging configured")
    return None


@dataclass
class LocalContext:
    level: str  # 'DEBUG', 'INFO' etc.
    format: str  # logging format string (using style '{')
    app_debug: bool  # Is the app in debug mode? Corresponding to current_app.debug
    filters: Sequence[LoggingFilters] = field(default_factory=list)  # filters to activate
    relative_time: bool = False  # use relative time as {asctime}

    def to_dict(self: Self) -> dict[str, Any]:
        res = asdict(self)
        res["level"] = logging.getLevelName(self.level)
        return res


def make_local_context(config: AuthServerConfig) -> LocalContext:
    """
    Local context is a place to put parameters for filters and formatters in logging dictConfigs.

    To provide typing and order, we keep them in a neat dataclass.
    """
    log_format = config.log_format
    if not log_format:
        log_format = DEFAULT_FORMAT

    log_level = config.log_level
    if config.debug:
        # Show debug log in debug mode
        log_level = "DEBUG"

    relative_time = config.testing

    try:
        local_context = LocalContext(
            level=log_level,
            format=log_format,
            app_debug=config.debug,
            filters=config.log_filters,
            relative_time=relative_time,
        )
    except (KeyError, AttributeError) as e:
        raise ConfigurationError(f"Could not initialize logging local_context. {type(e).__name__}: {e}")
    return local_context


def make_dictConfig(local_context: LocalContext) -> dict[str, Any]:
    """
    Create configuration for logging.dictConfig.

    Anything that needs to be parameterised should be put in LocalContext, which is
    a place to put arguments to various filters/formatters as well as anything else we
    need.
    """

    _available_filters = {
        # Only log debug messages if Flask app.debug is False
        LoggingFilters.DEBUG_FALSE: {
            "()": "eduid.common.logging.RequireDebugFalse",
            "app_debug": "cfg://local_context.app_debug",
        },
        # Only log debug messages if Flask app.debug is True
        LoggingFilters.DEBUG_TRUE: {
            "()": "eduid.common.logging.RequireDebugTrue",
            "app_debug": "cfg://local_context.app_debug",
        },
    }

    # Choose filters. Technically, they could all be included always,
    # since they have to appear in the 'filters' list of a handler in order to
    # be invoked, but we only include the requested ones for tidiness and readability.
    filters = {k: v for k, v in _available_filters.items() if k in local_context.filters}

    base_config = {
        "version": 1,
        "disable_existing_loggers": False,
        # Local variables
        "local_context": local_context.to_dict(),
        # Formatters
        "formatters": {
            "default": {
                "()": "auth_server.logging.CustomFormatter",
                "relative_time": "cfg://local_context.relative_time",
                "fmt": "cfg://local_context.format",
            },
        },
        # Filters
        "filters": filters,
        # Handlers
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "cfg://local_context.level",
                "formatter": "default",
                "filters": local_context.filters,
            },
        },
        # Loggers
        "root": {
            "handlers": ["console"],
            "level": "cfg://local_context.level",
        },
    }
    return base_config
