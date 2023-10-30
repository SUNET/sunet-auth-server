# -*- coding: utf-8 -*-
import logging.config
import sys
from typing import Optional

from loguru import logger

from auth_server.log_handler import InterceptHandler

__author__ = "lundberg"


LOGURU_FORMAT = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> |\
 <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"


# set up default python logger to be intercepted by loguru
logging.getLogger().handlers = [InterceptHandler()]
logging.getLogger().level = 0  # DEBUG


def init_logging(
    level: str = "INFO",
    colorize: bool = True,
    fmt: Optional[str] = None,
) -> None:
    if fmt is None:
        fmt = LOGURU_FORMAT
    logger.remove()  # Remove the default handler
    logger.add(sys.stderr, format=fmt, colorize=colorize, level="ERROR", enqueue=True)
    logger.add(sys.stdout, format=fmt, colorize=colorize, level=level, enqueue=True)
