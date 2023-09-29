# -*- coding: utf-8 -*-
from typing import Mapping, Optional

from starlette.responses import Response
from starlette.templating import Jinja2Templates as _Jinja2Templates
from starlette.templating import _TemplateResponse

__author__ = "lundberg"


# Workaround for bug in Starlette.
# https://github.com/encode/starlette/issues/472#issuecomment-612398116


class TestableJinja2Templates(_Jinja2Templates):
    def TemplateResponse(
        self,
        name: str,
        context: dict,
        status_code: int = 200,
        headers: Optional[Mapping[str, str]] = None,
        media_type: Optional[str] = None,
        background=None,
    ) -> _TemplateResponse:
        if "request" not in context:
            raise ValueError('context must include a "request" key')
        template = self.get_template(name)
        return CustomTemplateResponse(
            template,
            context,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )


class CustomTemplateResponse(_TemplateResponse):
    async def __call__(self, scope, receive, send) -> None:
        # context sending removed
        await Response.__call__(self, scope, receive, send)
