from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from .client import AuthServiceClient
from .exceptions import LicenseNotFoundError
from .repositories import AuditRepository, LicenseRepository
from .security import require_active_license


class AuthService:
    """
    Application Service that orchestrates operations by coordinating the AuthServiceClient,
    LicenseRepository, and AuditRepository.
    """

    def __init__(
        self,
        client: AuthServiceClient,
        licenses: LicenseRepository,
        audits: AuditRepository,
    ) -> None:
        self.client = client
        self.licenses = licenses
        self.audits = audits

    def verify_license(self) -> Dict[str, Any]:
        """
        Verifies the latest license from the repository with the AuthService.
        """
        existing = self.licenses.find_latest()
        if existing is None:
            raise LicenseNotFoundError("LICENSE_NOT_FOUND")

        result = self.client.verify_license(
            license_key=existing["license_key"],
            signature=existing.get("signature"),
        )

        data = result.get("data")
        if data is None:
            data = result

        verified_at = datetime.now(timezone.utc)
        self.licenses.mark_verified(
            existing["license_key"],
            verified_at,
        )

        self.audits.log(
            action="LICENSE_VERIFY",
            auditable_type="AuthLicense",
            auditable_id=existing.get("public_id"),
            properties={
                "license_key": existing["license_key"],
                "status": 1,
            },
        )

        return data

    def register_license(
        self,
        label: str,
        expired_at: str,
        notes: str = "",
        connection_id: int = 12,
    ) -> Dict[str, Any]:
        """
        Registers a license and saves it to the local repository as pending.
        """
        if not label:
            raise ValueError("Label is required")
        if not expired_at:
            raise ValueError("Expiry date is required")

        result = self.client.register_license(
            label=label,
            expired_at=expired_at,
            notes=notes,
            system_connection_id=connection_id,
        )

        data = result.get("data")
        if data is None:
            data = result

        public_id = data.get("public_id")
        license_key = data.get("license_key")
        signature = data.get("signature")

        # Save to repository (pending status is implied, handled by repo implementation)
        self.licenses.save_pending(
            public_id=public_id,
            license_key=license_key,
            signature=signature,
            expired_at=expired_at,
            notes=notes,
            connection_id=connection_id,
        )

        self.audits.log(
            action="LICENSE_REGISTER",
            auditable_type="AuthLicense",
            auditable_id=public_id,
            properties={
                "license_key": license_key,
                "label": label,
                "expired_at": expired_at,
            },
        )

        return data

    def get_system_connections(
        self,
        group_keys: Union[str, List[str]],
        client_register: List[str],
    ) -> Dict[str, Any]:
        """
        Retrieves system connections. Requires an active license.
        """
        license_record = require_active_license(self.licenses)
        return self.client.get_system_connections(
            group_keys=group_keys,
            client_register=client_register,
            license_key=license_record["license_key"],
            signature=license_record.get("signature"),
        )

    def register_client(
        self,
        connection_id: int,
        target_system_id: str,
        external_id: Union[int, str],
        description: str,
    ) -> Dict[str, Any]:
        """
        Registers a client. Requires an active license.
        """
        if not connection_id:
            raise ValueError("connection_id is required")
        if not target_system_id:
            raise ValueError("target_system_id is required")

        license_record = require_active_license(self.licenses)
        result = self.client.register_client(
            connection_id=connection_id,
            target_system_id=target_system_id,
            external_id=external_id,
            description=description,
            license_key=license_record["license_key"],
            signature=license_record.get("signature"),
        )

        data = result.get("data")
        if data is None:
            data = result

        self.audits.log(
            action="CLIENT_REGISTER",
            auditable_type="ClientRegister",
            auditable_id=str(external_id),
            properties={
                "connection_id": connection_id,
                "target_system_id": target_system_id,
            },
        )

        return data

    def authenticate(
        self,
        api_key: str,
        user_id: Union[int, str],
    ) -> Dict[str, Any]:
        """
        Authenticates a user/client. Requires an active license.
        """
        if not api_key:
            raise ValueError("api_key is required")
        if not user_id:
            raise ValueError("user_id is required")

        license_record = require_active_license(self.licenses)
        return self.client.authenticate(
            api_key=api_key,
            user_id=user_id,
            license_key=license_record["license_key"],
            signature=license_record.get("signature"),
        )

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verifies the access token. Requires an active license.
        """
        if not token:
            raise ValueError("token is required")

        license_record = require_active_license(self.licenses)
        return self.client.verify_token(
            token=token,
            license_key=license_record["license_key"],
            signature=license_record.get("signature"),
        )

    def request_kek(self) -> Dict[str, Any]:
        """
        Requests the Key Encryption Key (KEK). Requires an active license.
        """
        license_record = require_active_license(self.licenses)
        result = self.client.request_kek(
            license_key=license_record["license_key"],
            signature=license_record.get("signature"),
        )

        data = result.get("data")
        if data is None:
            data = result

        self.audits.log(
            action="KEK_REQUEST",
            auditable_type="KeyManagement",
            auditable_id=license_record.get("public_id"),
            properties={
                "license_key": license_record["license_key"],
            },
        )

        return data
