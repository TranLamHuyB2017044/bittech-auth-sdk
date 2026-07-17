import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional
from .exceptions import LicenseNotActiveError, ReplayAttackError
from .repositories import LicenseRepository, NonceStore


def create_request_metadata() -> dict[str, str]:
    """
    Generates metadata for API requests to prevent replay attacks.
    Includes a random 32-character hex nonce and the current Unix timestamp as a string.
    """
    return {
        "nonce": secrets.token_hex(16),
        "timestamp": str(int(time.time())),
    }


def require_active_license(repository: LicenseRepository) -> dict[str, Any]:
    """
    Guards routes/services by ensuring a valid, active, and unexpired license exists.
    Raises LicenseNotActiveError if check fails.
    """
    now = datetime.now(timezone.utc)
    license_record = repository.find_active(now)

    if license_record is None:
        raise LicenseNotActiveError("LICENSE_NOT_ACTIVE")

    if license_record.get("status") != 1:
        raise LicenseNotActiveError("LICENSE_NOT_ACTIVE")

    expired_at = license_record.get("expired_at")
    if expired_at is not None:
        if isinstance(expired_at, str):
            try:
                # Handle Z timezone suffix for python 3.8+ compatible parsing
                clean_str = expired_at.replace("Z", "+00:00")
                expired_at_dt = datetime.fromisoformat(clean_str)
            except Exception:
                raise LicenseNotActiveError("LICENSE_INVALID_EXPIRY")
        elif isinstance(expired_at, datetime):
            expired_at_dt = expired_at
        else:
            raise LicenseNotActiveError("LICENSE_INVALID_EXPIRY")

        if expired_at_dt.tzinfo is None:
            expired_at_dt = expired_at_dt.replace(tzinfo=timezone.utc)

        if expired_at_dt <= now:
            raise LicenseNotActiveError("LICENSE_EXPIRED")

    return license_record


def verify_replay_protection(
    nonce: str,
    timestamp_str: str,
    nonce_store: NonceStore,
    max_skew_seconds: int = 300,
) -> None:
    """
    Validates the nonce and timestamp to prevent replay attacks.
    """
    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        raise ReplayAttackError("INVALID_TIMESTAMP")

    now = int(time.time())
    if abs(now - timestamp) > max_skew_seconds:
        raise ReplayAttackError("TIMESTAMP_SKEW_TOO_LARGE")

    if nonce_store.contains(nonce):
        raise ReplayAttackError("REPLAY_ATTACK_DETECTED")

    # Add to store with a TTL slightly larger than the max allowed skew to prevent replay
    nonce_store.add(nonce, max_skew_seconds * 2)
