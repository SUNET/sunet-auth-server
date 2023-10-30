# -*- coding: utf-8 -*-
import logging
import sys

from loguru import _logger, logger

__author__ = "lundberg"


class InterceptHandler(logging.Handler):
    @logger.catch(default=True, onerror=lambda _: sys.exit(1))
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        skip_frames_in = [logging.__file__, __file__, _logger.__file__]
        while frame.f_code.co_filename in skip_frames_in:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())
