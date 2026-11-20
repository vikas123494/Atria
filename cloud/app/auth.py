"""JWT authentication plus database-backed tenant membership enforcement."""
import os

import jwt
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class TenantJWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/v1/"):
            header = request.headers.get("authorization", "")
            if not header.startswith("Bearer "):
                return JSONResponse({"detail": {"code": "UNAUTHENTICATED"}}, status_code=401)
            secret = os.getenv("DASHBOARD_JWT_SECRET", "")
            if len(secret) < 32:
                return JSONResponse({"detail": {"code": "AUTH_NOT_CONFIGURED"}}, status_code=503)
            try:
                claims = jwt.decode(
                    header[7:], secret, algorithms=["HS256"],
                    options={"require": ["exp", "sub", "tenant_id"]},
                    audience=os.getenv("DASHBOARD_JWT_AUDIENCE", "veilops-dashboard"),
                    issuer=os.getenv("DASHBOARD_JWT_ISSUER", "veilops-control"),
                )
                tenant_id, user_id = claims.get("tenant_id"), claims.get("sub")
                if not isinstance(tenant_id, str) or not tenant_id or not isinstance(user_id, str) or not user_id:
                    raise jwt.InvalidTokenError("tenant_id or sub missing")
                async with request.app.state.db_pool.acquire() as conn:
                    role = await conn.fetchval(
                        "SELECT role FROM memberships WHERE user_id=$1 AND tenant_id=$2",
                        user_id, tenant_id,
                    )
                if role is None:
                    return JSONResponse({"detail": {"code": "TENANT_MEMBERSHIP_REQUIRED"}}, status_code=403)
                request.state.tenant_id = tenant_id
                request.state.user_id = user_id
                request.state.tenant_role = role
            except jwt.PyJWTError:
                return JSONResponse({"detail": {"code": "UNAUTHENTICATED"}}, status_code=401)
            except Exception:
                return JSONResponse({"detail": {"code": "AUTHORIZATION_LOOKUP_FAILED"}}, status_code=503)
        return await call_next(request)
