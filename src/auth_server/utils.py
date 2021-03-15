# -*- coding: utf-8 -*-

from datetime import datetime, timezone

__author__ = 'lundberg'


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)
