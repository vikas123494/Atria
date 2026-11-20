"""JWT tenant authentication for dashboard APIs."""
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
                if not isinstance(claims.get("tenant_id"), str) or not claims["tenant_id"]:
                    raise jwt.InvalidTokenError("tenant_id missing")
                request.state.tenant_id = claims["tenant_id"]
                request.state.user_id = claims["sub"]
            except jwt.PyJWTError:
                return JSONResponse({"detail": {"code": "UNAUTHENTICATED"}}, status_code=401)
        return await call_next(request)
