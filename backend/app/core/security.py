"""
Security Utilities
===================
JWT token creation/validation, password hashing, and role-based
access control (RBAC) dependency injection for FastAPI routes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ── Password hashing ──────────────────────────────────────────────────────────
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Bearer token extractor ────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=True)


class UserRole(str, Enum):
    """RBAC roles in descending privilege order."""
    ADMIN = "admin"
    INCIDENT_COMMANDER = "incident_commander"
    SENIOR_ANALYST = "senior_analyst"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TokenPayload:
    """Decoded JWT payload representation."""

    def __init__(self, sub: str, role: UserRole, exp: datetime) -> None:
        self.sub = sub        # user_id
        self.role = role
        self.exp = exp

    @property
    def user_id(self) -> str:
        return self.sub


# ── Password utilities ────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Return bcrypt hash of plain-text password."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify plain-text password against bcrypt hash."""
    return _pwd_context.verify(plain, hashed)


# ── JWT utilities ─────────────────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    role: UserRole,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id: Subject claim (user identifier).
        role: User's RBAC role.
        expires_delta: Custom TTL. Defaults to settings value.

    Returns:
        Signed JWT string.
    """
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": user_id,
        "role": role.value,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT access token.

    Raises:
        HTTPException 401: If token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: Optional[str] = payload.get("sub")
        role_str: Optional[str] = payload.get("role")
        exp: Optional[int] = payload.get("exp")

        if not user_id or not role_str or not exp:
            raise credentials_exception

        return TokenPayload(
            sub=user_id,
            role=UserRole(role_str),
            exp=datetime.fromtimestamp(exp, tz=timezone.utc),
        )
    except (JWTError, ValueError) as exc:
        logger.warning("jwt_validation_failed", error=str(exc))
        raise credentials_exception from exc


# ── FastAPI dependency injectors ──────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> TokenPayload:
    """FastAPI dependency: decode JWT and return token payload."""
    return decode_token(credentials.credentials)


def require_role(*allowed_roles: UserRole):
    """
    FastAPI dependency factory for role-based access control.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role(UserRole.ADMIN))])

    Args:
        *allowed_roles: Roles permitted to access the endpoint.
    """
    async def _check(token: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if token.role not in allowed_roles:
            logger.warning(
                "rbac_denied",
                user_id=token.user_id,
                user_role=token.role,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[r.value for r in allowed_roles]}",
            )
        return token

    return _check


# ── Convenience role dependencies ─────────────────────────────────────────────
AdminRequired = Depends(require_role(UserRole.ADMIN))
AnalystRequired = Depends(require_role(
    UserRole.ADMIN, UserRole.INCIDENT_COMMANDER,
    UserRole.SENIOR_ANALYST, UserRole.ANALYST,
))
ViewerRequired = Depends(require_role(
    UserRole.ADMIN, UserRole.INCIDENT_COMMANDER,
    UserRole.SENIOR_ANALYST, UserRole.ANALYST, UserRole.VIEWER,
))
