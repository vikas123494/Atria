"""Create a one-time 15-minute enrollment token for an existing tenant.

Usage:
  python -m cloud.scripts.create_enrollment_token --tenant t_acme --region in
The plaintext token is printed once; only its SHA-256 digest is stored.
"""
import argparse
import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import asyncpg

from cloud.app.settings import Settings


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--region", choices=("in", "eu"), required=True)
    args = parser.parse_args()

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    conn = await asyncpg.connect(Settings().database_url)
    try:
        tenant = await conn.fetchrow(
            "SELECT tenant_id, home_region FROM tenants WHERE tenant_id=$1",
            args.tenant,
        )
        if not tenant:
            raise SystemExit("Unknown tenant; provision the tenant in the control plane first.")
        if tenant["home_region"] != args.region:
            raise SystemExit("Requested region does not match tenant home_region.")
        await conn.execute(
            """INSERT INTO enrollment_tokens(token_hash,tenant_id,region,expires_at)
               VALUES($1,$2,$3,$4)""",
            digest, args.tenant, args.region,
            datetime.now(timezone.utc) + timedelta(minutes=15),
        )
    finally:
        await conn.close()
    print(token)


if __name__ == "__main__":
    asyncio.run(main())
