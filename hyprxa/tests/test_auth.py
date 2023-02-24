import pytest
from typing import Tuple, Set

from hyprxa.auth import (
    on_error,
    requires, 
    BaseUser,
    AuthenticationClient,
    BaseAuthenticationBackend,
    TokenHandler,
    UserNotFound,
    AuthError,
)

from starlette.testclient import TestClient
from starlette.requests import HTTPConnection, Request
from starlette.authentication import AuthCredentials, AuthenticationError
from starlette.middleware.authentication import AuthenticationMiddleware

from fastapi import FastAPI, APIRouter, Depends

class BasicAuthClient(AuthenticationClient):
    "Basic authentication client with hardcoded credentials."
    def __init__(self, authenticated_users: Set):
        self.authenticated_users = authenticated_users

    def authenticate(self, username: str, password: str) -> bool:
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

@pytest.fixture(scope="session")
def token_handler() -> TokenHandler:
    return TokenHandler(key="secret", algorithm="HS256", expire=1800)

@pytest.fixture(scope="session")
def app(token_handler) -> FastAPI:
    app = FastAPI(title="Test Authentication")

    auth_client = BasicAuthClient({"admin", "user"})
    auth_backend = BasicAuth(client=auth_client, handler=token_handler)

    app.add_middleware(AuthenticationMiddleware, backend=auth_backend, on_error=on_error)

    router = APIRouter()

    @router.get("/whoami")
    def whoami(request: Request) -> dict:
        return {"username": request.user.username, "scopes": request.user.scopes}

    @router.get("/is_authenticated", response_model=bool)
    def is_authenticated(request: Request) -> bool:
        return request.user.is_authenticated

    @router.get("/requires_admin_scope", response_model=BaseUser)
    def requires_admin(request: Request, user: BaseUser = Depends(requires(["ADMIN"]))) -> BaseUser:
        return user.dict()
    
    app.include_router(router)

    return app

@pytest.fixture(scope="session")
def test_client(app: FastAPI) -> TestClient:
    with TestClient(app) as client:
        yield client

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
    assert response.json() ==  {'username': 'admin', 'scopes': ['authenticated', "ADMIN"]}

def test_requires_scopes(test_client: TestClient, token_handler: TokenHandler):
    admin_token = token_handler.issue(claims={"sub": "admin"})
    response = test_client.get("/requires_admin_scope", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200

    response = test_client.get("/requires_admin_scope", headers=None) # no headers
    assert response.status_code == 401

    user_token = token_handler.issue(claims={"sub": "user"})
    response = test_client.get("/requires_admin_scope", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 403
