"""Control-plane collector enrollment (Architecture §§13, 16)."""
import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from argon2 import PasswordHasher
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/v1", tags=["collector-control"])
_password_hasher = PasswordHasher()


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollment_token: str = Field(min_length=20, max_length=512)
    collector_pubinfo: dict = Field(default_factory=dict)
    version: str = Field(min_length=1, max_length=64)


@router.post("/enroll", status_code=201)
async def enroll(payload: EnrollRequest, request: Request):
    token_hash = hashlib.sha256(payload.enrollment_token.encode()).hexdigest()
    async with request.app.state.db_pool.acquire() as conn:
        async with conn.transaction():
            token = await conn.fetchrow(
                """SELECT tenant_id, region FROM enrollment_tokens
                   WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at > now()
                   FOR UPDATE""",
                token_hash,
            )
            if not token:
                raise HTTPException(401, detail={"code": "BAD_OR_EXPIRED_ENROLLMENT_TOKEN"})
            collector_id = "col_" + uuid.uuid4().hex[:16]
            collector_secret = secrets.token_urlsafe(32)
            secret_hash = _password_hasher.hash(collector_secret)
            ciphertext = request.app.state.secret_box.encrypt(collector_secret.encode())
            await conn.execute(
                """INSERT INTO collectors
                   (collector_id,tenant_id,region,secret_hash,secret_ciphertext,status,enrolled_at)
                   VALUES($1,$2,$3,$4,$5,'active',now())""",
                collector_id, token["tenant_id"], token["region"], secret_hash, ciphertext,
            )
            await conn.execute(
                "UPDATE enrollment_tokens SET consumed_at=now() WHERE token_hash=$1",
                token_hash,
            )

    return {
        "collector_id": collector_id,
        "collector_secret": collector_secret,
        "tenant_id": token["tenant_id"],
        "region": token["region"],
        "ingest_url": request.app.state.settings.ingest_base_url,
        "saas_pubkey": request.app.state.receipt_signer.public_key_b64(),
    }
