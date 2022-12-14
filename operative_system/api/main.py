from fastapi import FastAPI, Depends

from .routers.navigation import nav
from .routers.monitoring import monitor
from .routers.passkeys import passkeys
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

import os

print(os.getenv('SERGIOBOTOS_PWD'))

secret_key = '9c580e0641762c32eab407257d924c25d5c8dd44a67d9efb4403038ae783c37c'

middleware = [
    Middleware(
        SessionMiddleware,
        secret_key=secret_key,
        session_cookie='webauthn-demo',
        same_site='strict',
        https_only=False,
    )
]

app = FastAPI(middleware=middleware)

app.include_router(nav)
app.include_router(monitor)
app.include_router(passkeys)

@app.get('/')
async def root():
    return {'message': 'remember to go to /docs'}