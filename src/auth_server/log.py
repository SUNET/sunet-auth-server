# -*- coding: utf-8 -*-
import logging
import sys

from loguru import logger

__author__ = "lundberg"

LOGURU_FORMAT = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> |\
 <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"


class InterceptHandler(logging.Handler):
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


logging.getLogger().handlers = [InterceptHandler()]
logging.getLogger().level = 0  # DEBUG


def init_logging(
    level: str = "INFO",
    fmt=LOGURU_FORMAT,
    colorize: bool = True,
) -> None:
    logger.remove()  # Remove the default handler
    logger.add(sys.stderr, format=fmt, colorize=colorize, level="ERROR", enqueue=True)
    logger.add(sys.stdout, format=fmt, colorize=colorize, level=level, enqueue=True)
