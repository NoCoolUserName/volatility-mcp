"""Readable UTC timestamps and portable names for new derived artifacts."""
from datetime import datetime, timezone
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')


def timestamped_id() -> str:
    # Seconds are for readability; random suffixes prevent same-second collisions.
    return datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%SZ') + '-' + uuid.uuid4().hex[:12]
