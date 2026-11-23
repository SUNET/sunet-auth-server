import io
import logging
import queue
import threading
import time
from datetime import timedelta
from typing import Any, Self
from unittest import TestCase
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from pydantic import ValidationError
from starlette.testclient import TestClient

from auth_server.config import AuthServerConfig, LoggingFilters
from auth_server.logging import (
    DroppingQueueHandler,
    DroppingQueueListener,
    init_logging,
    make_dictConfig,
    make_local_context,
    stop_logging,
)
from auth_server.models.status import Status
from auth_server.routers.status import status_router

__author__ = "lundberg"


def _queue_handlers() -> list[DroppingQueueHandler]:
    return [h for h in logging.getLogger().handlers if isinstance(h, DroppingQueueHandler)]


class TestLogging(TestCase):
    def setUp(self: Self) -> None:
        root = logging.getLogger()
        self._handlers = list(root.handlers)
        self._level = root.level

    def tearDown(self: Self) -> None:
        stop_logging()
        root = logging.getLogger()
        for handler in list(root.handlers):
            if handler not in self._handlers:
                root.removeHandler(handler)
        for handler in self._handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(self._level)

    @staticmethod
    def _config(**kwargs: object) -> AuthServerConfig:
        return AuthServerConfig(auth_token_issuer="x", **kwargs)  # type: ignore[arg-type]

    def test_queue_handler_with_running_listener(self: Self) -> None:
        init_logging(self._config())
        handlers = _queue_handlers()
        self.assertEqual(1, len(handlers))
        self.assertEqual(1, len(logging.getLogger().handlers))
        listener = handlers[0].listener
        assert listener is not None
        self.assertIsNotNone(listener._thread)

    def test_records_reach_console(self: Self) -> None:
        stream = io.StringIO()
        with patch("sys.stderr", stream), patch("sys.stdout", stream):
            init_logging(self._config(testing=True, log_level="INFO"))
            logging.getLogger("test.queue").warning("hello from queue")
            stop_logging()
        out = stream.getvalue()
        self.assertIn("hello from queue", out)
        self.assertRegex(out, r"\d+\.\d{3}s")

    def test_queue_full_drops_silently(self: Self) -> None:
        handler = DroppingQueueHandler(queue.Queue(maxsize=1))
        logger = logging.getLogger("test.full")
        logger.propagate = False
        logger.addHandler(handler)
        try:
            with patch.object(logging.Handler, "handleError") as handle_error:
                for i in range(5):
                    logger.warning(f"msg {i}")
            handle_error.assert_not_called()
        finally:
            logger.removeHandler(handler)
            logger.propagate = True
        self.assertEqual(4, handler.dropped)

    def test_reinit_does_not_leak_threads(self: Self) -> None:
        before = threading.active_count()
        for _ in range(3):
            init_logging(self._config())
        self.assertLessEqual(threading.active_count(), before + 1)

    def test_stop_logging_twice(self: Self) -> None:
        init_logging(self._config())
        stop_logging()
        stop_logging()

    def test_filters_enabled(self: Self) -> None:
        for flt, debug, expect in [
            (LoggingFilters.DEBUG_FALSE, False, True),
            (LoggingFilters.DEBUG_FALSE, True, False),
            (LoggingFilters.DEBUG_TRUE, True, True),
            (LoggingFilters.DEBUG_TRUE, False, False),
        ]:
            with self.subTest(flt=flt, debug=debug):
                stream = io.StringIO()
                with patch("sys.stderr", stream), patch("sys.stdout", stream):
                    init_logging(self._config(log_filters=[flt], debug=debug))
                    logging.getLogger("test.filter").error("filter probe")
                    stop_logging()
                self.assertEqual(expect, "filter probe" in stream.getvalue())

    def test_queue_size_from_config(self: Self) -> None:
        local_context = make_local_context(self._config(log_queue_size=1234))
        self.assertEqual(1234, local_context.queue_size)
        self.assertEqual(1234, make_dictConfig(local_context)["local_context"]["queue_size"])
        init_logging(self._config(log_queue_size=1234))
        q = _queue_handlers()[0].queue
        assert isinstance(q, queue.Queue)
        self.assertEqual(1234, q.maxsize)

    def _manual_pipeline(
        self: Self, maxsize: int, interval: float = 60.0, limit: int | None = None
    ) -> tuple[DroppingQueueHandler, DroppingQueueListener, io.StringIO, logging.Logger]:
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        console.setFormatter(logging.Formatter("{levelname}|{name}|{message}", style="{"))
        q: queue.Queue[Any] = queue.Queue(maxsize=maxsize)
        handler = DroppingQueueHandler(q, max_message_length=limit)
        listener = DroppingQueueListener(q, console, respect_handler_level=True)
        listener.attach(handler, interval)
        logger = logging.getLogger("test.manual")
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(setattr, logger, "propagate", True)
        return handler, listener, stream, logger

    def test_drop_report_emitted(self: Self) -> None:
        handler, listener, stream, logger = self._manual_pipeline(maxsize=2)
        for i in range(5):
            logger.info(f"msg {i}")
        self.assertEqual(3, handler.dropped)
        listener.start()
        listener.stop()
        out = stream.getvalue()
        self.assertIn("WARNING|auth_server.logging|dropped 3 log records since last report (3 total)", out)
        self.assertEqual(1, out.count("dropped "))

    def test_drop_report_rate_limited(self: Self) -> None:
        handler, listener, stream, logger = self._manual_pipeline(maxsize=1, interval=60.0)
        now = [100.0]
        listener._clock = lambda: now[0]
        logger.info("a")
        logger.info("b")  # dropped
        listener.start()
        for _ in range(100):
            if "dropped 1 " in stream.getvalue():
                break
            threading.Event().wait(0.01)
        self.assertEqual(1, stream.getvalue().count("dropped "))
        # second burst within the interval: no new report
        now[0] = 130.0
        handler.dropped += 4
        logger.info("c")
        for _ in range(100):
            if "|c" in stream.getvalue():
                break
            threading.Event().wait(0.01)
        self.assertEqual(1, stream.getvalue().count("dropped "))
        # after the interval a second report follows the next record
        now[0] = 200.0
        logger.info("d")
        for _ in range(100):
            if "dropped 4 " in stream.getvalue():
                break
            threading.Event().wait(0.01)
        listener.stop()
        out = stream.getvalue()
        self.assertIn("dropped 4 log records since last report (5 total)", out)
        self.assertEqual(2, out.count("dropped "))

    def test_final_report_on_stop(self: Self) -> None:
        stream = io.StringIO()
        with patch("sys.stderr", stream), patch("sys.stdout", stream):
            init_logging(self._config(testing=True, log_level="INFO", log_queue_size=10))
            handler = _queue_handlers()[0]
            listener = handler.listener
            assert isinstance(listener, DroppingQueueListener)
            # pretend a report was just sent, so only the final flush can report
            listener._last_report_time = time.monotonic()
            handler.dropped = 7
            stop_logging()
        self.assertIn("dropped 7 log records since last report (7 total)", stream.getvalue())

    def test_truncation(self: Self) -> None:
        handler, listener, stream, logger = self._manual_pipeline(maxsize=100, limit=100)
        logger.info("x" * 1_000_000)
        logger.info("short")
        logger.info("fmt %s", "arg")
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("failed")
        logger.info(12345)
        listener.start()
        listener.stop()
        lines = stream.getvalue()
        self.assertIn("x" * 100 + "... [truncated 999900 chars]", lines)
        self.assertNotIn("x" * 101, lines)
        self.assertIn("INFO|test.manual|short\n", lines)
        self.assertIn("INFO|test.manual|fmt arg\n", lines)
        self.assertIn("Traceback (most recent call last)", lines)
        self.assertIn("[truncated 106 chars]", lines)
        self.assertIn("12345", lines)

    def test_truncation_keeps_traceback_below_limit(self: Self) -> None:
        handler, listener, stream, logger = self._manual_pipeline(maxsize=10, limit=100000)
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("failed")
        listener.start()
        listener.stop()
        self.assertNotIn("truncated", stream.getvalue())
        self.assertIn("Traceback", stream.getvalue())

    def test_prepare_non_str_msg(self: Self) -> None:
        handler = DroppingQueueHandler(queue.Queue(), max_message_length=5)
        record = logging.LogRecord("n", logging.INFO, "p", 1, 12345678, None, None)
        self.assertEqual("12345... [truncated 3 chars]", handler.prepare(record).msg)

    def test_max_message_length_from_config(self: Self) -> None:
        init_logging(self._config(log_max_message_length=77, log_drop_report_interval=timedelta(seconds=5)))
        handler = _queue_handlers()[0]
        self.assertEqual(77, handler.max_message_length)
        listener = handler.listener
        assert isinstance(listener, DroppingQueueListener)
        self.assertEqual(5.0, listener.report_interval)
        self.assertIs(handler, listener.drop_source)

    def test_status_exposes_dropped(self: Self) -> None:
        app = FastAPI()
        app.include_router(status_router)
        init_logging(self._config())
        _queue_handlers()[0].dropped = 42
        with (
            patch("auth_server.routers.status._mongodb_health_check", AsyncMock(return_value=True)),
            TestClient(app) as client,
        ):
            body = client.get("/status/healthy").json()
        self.assertEqual(42, body["log_records_dropped"])
        self.assertEqual(Status.OK.value, body["status"])

    def test_config_validation(self: Self) -> None:
        for kwargs in ({"log_max_message_length": 0}, {"log_drop_report_interval": timedelta(0)}):
            with self.subTest(**kwargs), self.assertRaises(ValidationError):
                self._config(**kwargs)
