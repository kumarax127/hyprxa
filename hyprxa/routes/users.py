from fastapi import APIRouter, Depends, Request

from hyprxa.auth.models import BaseUser
from hyprxa.auth.scopes import requires
from hyprxa.exceptions import NotConfiguredError



router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/whoami", response_model=BaseUser, dependencies=[Depends(requires())])
async def get_user(request: Request) -> BaseUser:
    """Retrieve user information for current logged in user."""
    return request.user.dict()