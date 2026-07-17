from datetime import datetime
from typing import Any, Optional, Protocol


class LicenseRepository(Protocol):
    """
    Protocol definition for managing license storage and retrieval.
    Implementation is database-specific and supplied by the client application.
    """

    def find_latest(self) -> Optional[dict[str, Any]]:
        ...

    def find_active(self, now: datetime) -> Optional[dict[str, Any]]:
        ...

    def save_pending(
        self,
        *,
        public_id: str,
        license_key: str,
        signature: Optional[str],
        expired_at: datetime,
        notes: Optional[str],
        connection_id: int = 12,
    ) -> dict[str, Any]:
        ...

    def mark_verified(
        self,
        license_key: str,
        verified_at: datetime,
    ) -> None:
        ...


class AuditRepository(Protocol):
    """
    Protocol definition for security and action audit logging.
    Implementation is database-specific and supplied by the client application.
    """

    def log(
        self,
        *,
        action: str,
        auditable_type: Optional[str] = None,
        auditable_id: Optional[str] = None,
        properties: Optional[dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        ...


class NonceStore(Protocol):
    """
    Protocol definition for tracking request nonces to prevent replay attacks.
    """

    def contains(self, nonce: str) -> bool:
        ...

    def add(self, nonce: str, ttl_seconds: int) -> None:
        ...
