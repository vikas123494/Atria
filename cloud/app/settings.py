"""Environment-backed settings for VeilOps Cloud Core."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://veilops:veilops_dev_only@localhost:5432/veilops",
    )
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    database_pool_max: int = int(os.getenv("DATABASE_POOL_MAX", "10"))
