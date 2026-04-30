from enum import StrEnum, unique

from pydantic import BaseModel

__author__ = "lundberg"


@unique
class Status(StrEnum):
    # STATUS_x_ is less ambiguous when pattern matching than just 'x'
    OK = "STATUS_OK_"
    FAIL = "STATUS_FAIL_"


class StatusResponse(BaseModel):
    status: Status
    version: int = 1
