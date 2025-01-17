from datetime import UTC, datetime

__author__ = "lundberg"


def utc_now() -> datetime:
    return datetime.now(tz=UTC)
