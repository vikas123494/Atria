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
    region: str = os.getenv("VEILOPS_REGION", "in")
    ingest_base_url: str = os.getenv("INGEST_BASE_URL", "http://localhost:8000/v1")
    ingest_stream: str = os.getenv("INGEST_STREAM", "veilops:ingest")
    ingest_rate_per_minute: int = int(os.getenv("INGEST_RATE_PER_MINUTE", "600"))
