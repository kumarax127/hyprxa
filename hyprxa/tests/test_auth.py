import pytest
import logging 
import datetime
import functools

from jose import ExpiredSignatureError, JWTError, jwt

from typing import Tuple, Set

from hyprxa.auth import (
    on_error,
    requires,
    BaseUser,
    AuthenticationClient,
    BaseAuthenticationBackend,
    DebugAuthenticationMiddleware,
    TokenHandler,
    UserNotFound,
    AuthError,
    Token,
    token, 
    debug_token
)

from hyprxa.exceptions import NotConfiguredError

from starlette.testclient import TestClient
from starlette.requests import HTTPConnection, Request
from starlette.authentication import AuthCredentials, AuthenticationError
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware import Middleware

from fastapi import FastAPI, APIRouter, Depends

log = logging.getLogger("hyprxa.auth")

### Setup ###
class BasicAuthClient(AuthenticationClient):
    "Basic authentication client with hardcoded credentials."
    def __init__(self, authenticated_users: Set):
        self.authenticated_users = authenticated_users

    async def authenticate(self, username: str, password: str) -> bool:
        return username in self.authenticated_users

    def get_user(self, username: str) -> BaseUser:
        if username in self.authenticated_users:
            scopes = {"authenticated"} if username != "admin" else {"authenticated", "ADMIN"}
            return BaseUser(username=username, scopes=scopes)
        raise UserNotFound(username)

class BasicAuth(BaseAuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection) -> Tuple[AuthCredentials, BaseUser] | None:
        if "Authorization" not in conn.headers:
            return None

        auth = conn.headers.get("Authorization")
        if auth is None:
            return

        scheme, credentials = auth.split()

        if scheme.lower() != "bearer":
            return
        username = self.handler.validate(credentials)

        if username is None:
            return

        try:
            user = self.client.get_user(username)
        except AuthError as err:
            raise AuthenticationError(str(err)) from err

        return AuthCredentials(user.scopes), user

@pytest.fixture(scope="module")
def token_handler() -> TokenHandler:
    handler = TokenHandler(key="secret", algorithm="HS256", expire=1800)
    yield handler
    handler.expire = 1800

@pytest.fixture(scope="module")
def app(token_handler: TokenHandler) -> FastAPI:
    app = FastAPI(title="Test Authentication")

    auth_client = BasicAuthClient({"admin", "user"})
    auth_backend = BasicAuth(client=auth_client, handler=token_handler)

    app.add_middleware(AuthenticationMiddleware, backend=auth_backend, on_error=on_error)
    app.authentication_middleware = Middleware(AuthenticationMiddleware, backend=auth_backend, on_error=on_error)

    router = APIRouter()

    @router.get("/whoami")
    def whoami(request: Request) -> dict:
        return {"username": request.user.username, "scopes": sorted(list(request.user.scopes))}

    @router.get("/is_authenticated", response_model=bool)
    def is_authenticated(request: Request) -> bool:
        return request.user.is_authenticated

    @router.get("/requires_admin_scope", response_model=BaseUser)
    def requires_admin(request: Request, user: BaseUser = Depends(requires(["ADMIN"]))) -> BaseUser:
        return user.dict()

    @router.get("/raise_on_no_scopes", response_model=BaseUser)
    def requires_scopes(request: Request, user: BaseUser = Depends(requires(raise_on_no_scopes=True))):
        return user.dict()

    app.include_router(router)

    app.add_api_route("/token", token, response_model=Token, methods=["POST"])
    app.add_api_route("/debug_token", debug_token, response_model=Token, methods=["POST"])

    return app

@pytest.fixture(scope="module")
def test_client(app: FastAPI) -> TestClient:
    with TestClient(app) as client:
        yield client

### Tests ###
def test_invalid_headers(test_client: TestClient):
    response = test_client.get("/is_authenticated")
    assert response.status_code == 200
    assert response.content == b'false'

def test_valid_headers(test_client: TestClient, token_handler: TokenHandler):
    token = token_handler.issue(claims={"sub": "admin"})
    response = test_client.get("/is_authenticated", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.content == b'true'

def test_invalid_user(test_client: TestClient, token_handler: TokenHandler):
    token = token_handler.issue(claims={"sub": "non_user"})
    response = test_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 500
    assert response.json().get("detail") == "The request cannot be completed. non_user not found."

def test_valid_user(test_client: TestClient, token_handler: TokenHandler):
    token = token_handler.issue(claims={"sub": "admin"})
    response = test_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() ==  {'username': 'admin', 'scopes': ["ADMIN", "authenticated"]}

def test_requires_scopes(test_client: TestClient, token_handler: TokenHandler):
    admin_token = token_handler.issue(claims={"sub": "admin"})
    response = test_client.get("/requires_admin_scope", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200

    response = test_client.get("/requires_admin_scope", headers=None) # no headers
    assert response.status_code == 401

    user_token = token_handler.issue(claims={"sub": "user"})
    response = test_client.get("/requires_admin_scope", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 403

def test_expired_token(test_client: TestClient, token_handler: TokenHandler):
    token_handler.expire = datetime.timedelta(seconds=-1)
    token = token_handler.issue({"sub": "admin"}) 
    assert token_handler.validate(token) is None
    token_handler.expire = datetime.timedelta(seconds=1800) # clean up maybe can use parametrized scope

def test_invalid_token(token_handler: TokenHandler):
    assert token_handler.validate("invalid_token") is None

def test_requires_scopes_raise_on_no_scopes(test_client: TestClient, token_handler: TokenHandler):
    with pytest.raises(NotConfiguredError):
        token = token_handler.issue({"sub": "admin"})
        test_client.headers = {"Authorization": f"Bearer {token}"}
        test_client.get("/raise_on_no_scopes")

def test_debug_token_route(test_client: TestClient, token_handler: TokenHandler):
    response = test_client.post("/debug_token", data={"username": "this_does_not_matter", "password": "does not matter"})
    assert response.status_code == 200

def test_token_route(test_client, token_handler: TokenHandler):
    response = test_client.post("/token", data={"username": "admin", "password": "password"})
    assert response.status_code == 200
    assert response.json().get("access_token") is not None

    response = test_client.post("/token", data={"username": "not a user", "password": "password"})
    assert response.status_code == 401

def test_debug_middleware():
    app = FastAPI(title="Test Authentication")

    admin_user = BaseUser(username="admin", scopes=["ADMIN"])

    DebugAuthenticationMiddleware.set_user(BaseUser(username="admin", scopes={"ADMIN"}))

    # backend should not matter here
    app.add_middleware(DebugAuthenticationMiddleware, backend=None, on_error=on_error)

    @app.get("/requires_admin_scope", response_model=BaseUser)
    def requires_admin(request: Request, user: BaseUser = Depends(requires(["ADMIN"]))) -> BaseUser:
        return user.dict()

    with TestClient(app) as client:
        response = client.get("/requires_admin_scope", headers={}) # no headers needed for debug
        assert response.status_code == 200
        assert BaseUser(**response.json()) == admin_user