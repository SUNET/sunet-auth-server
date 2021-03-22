# -*- coding: utf-8 -*-

from auth_server.api import init_auth_server_api
from auth_server.config import Environment

__author__ = 'lundberg'


app = init_auth_server_api()

if __name__ == '__main__':
    import uvicorn

    if app.state.config.environment is Environment.DEV:
        uvicorn.run('run:app', reload=True)
    else:
        uvicorn.run('run:app')
