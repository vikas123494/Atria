"""Collector request authentication and replay protection (Architecture §16)."""
import base64
import hashlib
import hmac
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class CollectorAuth:
    collector_id: str
    timestamp: str
    nonce: str


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signature_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return "\n".join((method.upper(), path, timestamp, nonce, body_sha256(body))).encode()


def verify_hmac(secret: bytes, method: str, path: str, timestamp: str, nonce: str,
                body: bytes, supplied_signature: str) -> bool:
    expected = base64.b64encode(
        hmac.new(secret, signature_message(method, path, timestamp, nonce, body),
                 hashlib.sha256).digest()
    ).decode("ascii")
    return hmac.compare_digest(expected, supplied_signature)


async def authenticate_collector(request: Request, body: bytes) -> tuple[CollectorAuth, dict]:
    headers = request.headers
    collector_id = headers.get("x-veilops-collector")
    timestamp = headers.get("x-veilops-timestamp")
    nonce = headers.get("x-veilops-nonce")
    signature = headers.get("x-veilops-signature")
    if not all((collector_id, timestamp, nonce, signature)):
        raise HTTPException(401, detail={"code": "BAD_SIGNATURE"})

    if len(nonce) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in nonce):
        raise HTTPException(401, detail={"code": "BAD_SIGNATURE"})
    try:
        try:
            stamp = int(timestamp)
        except ValueError:
            from datetime import datetime
            stamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        raise HTTPException(401, detail={"code": "STALE_TIMESTAMP"})
    if abs(time.time() - stamp) > 300:
        raise HTTPException(401, detail={"code": "STALE_TIMESTAMP"})

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT collector_id, tenant_id, region, status, secret_ciphertext
               FROM collectors WHERE collector_id=$1 AND revoked_at IS NULL""",
            collector_id,
        )
    if not row or row["status"] != "active" or not row["secret_ciphertext"]:
        raise HTTPException(401, detail={"code": "BAD_SIGNATURE"})

    secret = request.app.state.secret_box.decrypt(bytes(row["secret_ciphertext"]))
    request_path = request.url.path + (('?' + request.url.query) if request.url.query else '')
    if not verify_hmac(secret, request.method, request_path, timestamp, nonce, body, signature):
        raise HTTPException(401, detail={"code": "BAD_SIGNATURE"})

    redis_key = f"nonce:{collector_id}:{nonce}"
    accepted = await request.app.state.redis.set(redis_key, "1", ex=600, nx=True)
    if not accepted:
        raise HTTPException(409, detail={"code": "NONCE_REUSED"})
    return CollectorAuth(collector_id, timestamp, nonce), dict(row)
