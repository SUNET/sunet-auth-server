import atexit
import logging
import logging.config
import logging.handlers
import queue
import time
from collections.abc import Callable, Sequence
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


class DroppingQueueHandler(logging.handlers.QueueHandler):
    """
    QueueHandler that never blocks the caller. If the queue is full the record is dropped and counted.

    handleError is deliberately not called: it writes to stderr synchronously, which is what the queue avoids.
    The drop count is reported by DroppingQueueListener from the listener thread.

    Messages longer than max_message_length are truncated, as the queue is bounded by record count, not bytes.
    """

    def __init__(self: Self, queue: queue.Queue[Any], max_message_length: int | None = None) -> None:
        super().__init__(queue)
        self.dropped: int = 0
        self.max_message_length = max_message_length

    def prepare(self: Self, record: logging.LogRecord) -> logging.LogRecord:
        record = super().prepare(record)
        limit = self.max_message_length
        msg = record.msg
        if limit is not None and isinstance(msg, str) and len(msg) > limit:
            record.msg = f"{msg[:limit]}... [truncated {len(msg) - limit} chars]"
        return record

    def enqueue(self: Self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.dropped += 1


class DroppingQueueListener(logging.handlers.QueueListener):
    """
    QueueListener that reports records dropped by its DroppingQueueHandler.

    Reporting runs on the listener thread only, so a stalled sink never stalls producers. At most one synthetic
    WARNING record is emitted per report interval, and a final one when the listener is stopped.
    """

    def __init__(
        self: Self, queue: queue.Queue[Any], *handlers: logging.Handler, respect_handler_level: bool = False
    ) -> None:
        super().__init__(queue, *handlers, respect_handler_level=respect_handler_level)
        self.drop_source: DroppingQueueHandler | None = None
        self.report_interval: float = 60.0
        self._clock: Callable[[], float] = time.monotonic
        self._last_reported: int = 0
        self._last_report_time: float | None = None

    def attach(self: Self, drop_source: DroppingQueueHandler, report_interval: float) -> None:
        self.drop_source = drop_source
        self.report_interval = report_interval

    def handle(self: Self, record: logging.LogRecord) -> None:
        super().handle(record)
        self._report_drops()

    def stop(self: Self) -> None:
        had_thread = self._thread is not None
        super().stop()
        if had_thread:
            self._report_drops(force=True)

    def _report_drops(self: Self, force: bool = False) -> None:
        source = self.drop_source
        if source is None:
            return
        total = source.dropped
        new = total - self._last_reported
        if new <= 0:
            return
        now = self._clock()
        if not force and self._last_report_time is not None and now - self._last_report_time < self.report_interval:
            return
        self._last_reported = total
        self._last_report_time = now
        record = logging.LogRecord(
            name=__name__,
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg=f"dropped {new} log records since last report ({total} total) because the log queue was full",
            args=None,
            exc_info=None,
        )
        super().handle(record)


_atexit_registered = False


def _queue_handlers() -> list[DroppingQueueHandler]:
    return [h for h in logging.getLogger().handlers if isinstance(h, DroppingQueueHandler)]


def dropped_log_records() -> int:
    """Total number of log records dropped by the root queue handler(s) because the queue was full."""
    return sum(h.dropped for h in _queue_handlers())


def stop_logging() -> None:
    """Stop queue listeners on the root logger, flushing queued records. Safe to call repeatedly."""
    for handler in _queue_handlers():
        listener = getattr(handler, "listener", None)
        if listener is None:
            continue
        try:
            listener.stop()
        except queue.Full:
            # Sentinel could not be enqueued. The listener thread is a daemon thread, leave it.
            pass


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
    global _atexit_registered
    stop_logging()
    if not _atexit_registered:
        atexit.register(stop_logging)
        _atexit_registered = True

    local_context = make_local_context(config)
    logging_config = make_dictConfig(local_context)

    logging_config = merge_config(logging_config, config.logging_config)

    logging.config.dictConfig(logging_config)
    # dictConfig creates the listener (as handler.listener) but does not start it
    for handler in _queue_handlers():
        if handler.listener is not None:
            if isinstance(handler.listener, DroppingQueueListener):
                handler.listener.attach(handler, config.log_drop_report_interval.total_seconds())
            handler.listener.start()
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
    queue_size: int = 10000  # max number of log records buffered for the listener thread
    max_message_length: int = 8192  # longer formatted messages are truncated before being queued

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
            queue_size=config.log_queue_size,
            max_message_length=config.log_max_message_length,
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
            "()": "auth_server.logging.RequireDebugFalse",
            "app_debug": "cfg://local_context.app_debug",
        },
        # Only log debug messages if Flask app.debug is True
        LoggingFilters.DEBUG_TRUE: {
            "()": "auth_server.logging.RequireDebugTrue",
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
            # Root logs to this non-blocking queue, a listener thread feeds the console handler
            "queue": {
                "class": "auth_server.logging.DroppingQueueHandler",
                "handlers": ["console"],
                "listener": "auth_server.logging.DroppingQueueListener",
                "max_message_length": local_context.max_message_length,
                "respect_handler_level": True,
                # Literal int: dictConfig does not resolve cfg:// in the kwargs of the nested queue factory
                "queue": {"()": "queue.Queue", "maxsize": local_context.queue_size},
            },
        },
        # Loggers
        "root": {
            "handlers": ["queue"],
            "level": "cfg://local_context.level",
        },
    }
    return base_config
