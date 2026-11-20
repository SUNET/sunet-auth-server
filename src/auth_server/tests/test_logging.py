import io
import logging
import queue
import threading
from typing import Self
from unittest import TestCase
from unittest.mock import patch

from auth_server.config import AuthServerConfig, LoggingFilters
from auth_server.logging import DroppingQueueHandler, init_logging, make_dictConfig, make_local_context, stop_logging

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
