from .client import AuthServiceClient, HttpTransport, HttpxTransport
from .exceptions import (
    AuthServiceRequestError,
    BittechAuthError,
    LicenseConfigError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    ReplayAttackError,
)
from .license import (
    calculate_license_seed,
    canonical_json_stringify,
    load_license_config,
    load_license_seed,
)
from .repositories import AuditRepository, LicenseRepository, NonceStore
from .security import create_request_metadata, require_active_license, verify_replay_protection
from .services import AuthService

__all__ = [
    "AuthService",
    "AuthServiceClient",
    "HttpTransport",
    "HttpxTransport",
    "LicenseRepository",
    "AuditRepository",
    "NonceStore",
    "calculate_license_seed",
    "canonical_json_stringify",
    "load_license_config",
    "load_license_seed",
    "create_request_metadata",
    "require_active_license",
    "verify_replay_protection",
]
