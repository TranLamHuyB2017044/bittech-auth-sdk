import os
import httpx
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union
from .license import load_license_seed
from .security import create_request_metadata
from .exceptions import AuthServiceRequestError


class HttpTransport(Protocol):
    """
    Protocol definition for HTTP transport layer.
    Allows clients to inject custom HTTP adapters (e.g., using requests, httpx, etc.).
    """

    def get(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ...

    def post(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ...


class HttpxTransport:
    """
    Default implementation of HttpTransport using synchronous httpx client.
    """

    def get(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with httpx.Client() as client:
            response = client.request("GET", url, headers=headers, json=json, timeout=15.0)
            if response.status_code >= 400:
                try:
                    error_detail = response.json()
                except Exception:
                    error_detail = response.text
                raise httpx.HTTPStatusError(
                    f"HTTP Error {response.status_code}: {error_detail}",
                    request=response.request,
                    response=response
                )
            return response.json()

    def post(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with httpx.Client() as client:
            response = client.post(
                url, headers=headers, json=json, files=files, data=data, timeout=15.0
            )
            if response.status_code >= 400:
                try:
                    error_detail = response.json()
                except Exception:
                    error_detail = response.text
                raise httpx.HTTPStatusError(
                    f"HTTP Error {response.status_code}: {error_detail}",
                    request=response.request,
                    response=response
                )
            return response.json()


class AuthServiceClient:
    """
    Client for interacting with Bittech AuthService APIs.
    """

    def __init__(
        self,
        system_id: str,
        license_config_path: Union[str, Path],
        transport: HttpTransport,
        auth_api_url: Optional[str] = None,
    ) -> None:
        if auth_api_url is None:
            auth_api_url = os.getenv("AUTH_API_URL")
        
        if not auth_api_url:
            raise ValueError("auth_api_url is required (either pass it to AuthServiceClient or set the AUTH_API_URL environment variable)")

        self.auth_api_url = auth_api_url.rstrip("/")
        self.system_id = system_id
        self.license_config_path = Path(license_config_path)
        self.transport = transport

    def register_license(
        self,
        label: str,
        expired_at: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Registers the system license file with the AuthService.
        """
        try:
            seed, _ = load_license_seed(self.license_config_path)
            with self.license_config_path.open("rb") as license_file:
                return self.transport.post(
                    f"{self.auth_api_url}/api/license/register",
                    headers={"Accept": "application/json"},
                    files={
                        "license_config": (
                            self.license_config_path.name,
                            license_file,
                            "application/octet-stream",
                        )
                    },
                    data={
                        "license_seed": seed,
                        "label": label,
                        "expired_at": expired_at,
                        "notes": notes,
                    },
                )
        except Exception as e:
            raise AuthServiceRequestError(f"Register license failed: {e}")

    def verify_license(
        self,
        license_key: str,
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Verifies the validity of the current license.
        """
        try:
            seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "license_key": license_key,
                "license_seed": seed,
                "system_id": self.system_id,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.post(
                f"{self.auth_api_url}/api/license/verify",
                headers={"Accept": "application/json"},
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Verify license failed: {e}")

    def get_system_connections(
        self,
        group_keys: Union[str, List[str]],
        client_register: List[str],
        license_key: Optional[str],
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Retrieves system connection details from the AuthService.
        """
        try:
            metadata = create_request_metadata()
            payload = {
                "source_system_id": self.system_id,
                "group_key": group_keys,
                "client_register": client_register,
                "license_key": license_key or "",
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.get(
                f"{self.auth_api_url}/api/system-connections/get",
                headers={"Accept": "application/json"},
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Get system connections failed: {e}")

    def register_client(
        self,
        connection_id: int,
        target_system_id: str,
        external_id: Union[int, str],
        description: str,
        license_key: Optional[str],
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Registers a new client under the current system.
        """
        try:
            seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "system_connection_id": connection_id,
                "target_system_id": target_system_id,
                "source_system_id": self.system_id,
                "external_id": external_id,
                "description": description,
                "license_key": license_key or "",
                "license_seed": seed,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.post(
                f"{self.auth_api_url}/api/client-registers",
                headers={"Accept": "application/json"},
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Register client failed: {e}")

    def authenticate(
        self,
        api_key: str,
        user_id: Union[int, str],
        license_key: Optional[str],
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Authenticates a user and retrieves an access token.
        """
        try:
            metadata = create_request_metadata()
            payload = {
                "source_system_id": self.system_id,
                "license_key": license_key or "",
                "api_key": api_key,
                "user_id": user_id,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.post(
                f"{self.auth_api_url}/api/authenticate",
                headers={"Accept": "application/json"},
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Authenticate failed: {e}")

    def verify_token(
        self,
        token: str,
        license_key: Optional[str],
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Verifies a Bearer token validity.
        """
        try:
            metadata = create_request_metadata()
            payload = {
                "source_system_id": self.system_id,
                "license_key": license_key or "",
                "api_key": "",
                "user_id": "",
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.post(
                f"{self.auth_api_url}/api/verify-token",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Verify token failed: {e}")

    def request_kek(
        self,
        license_key: Optional[str],
        signature: Optional[str],
    ) -> Dict[str, Any]:
        """
        Requests the Key Encryption Key (KEK) from the AuthService.
        """
        try:
            seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "license_key": license_key or "",
                "license_seed": seed,
                "system_id": self.system_id,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            return self.transport.post(
                f"{self.auth_api_url}/api/kek/request",
                headers={"Accept": "application/json"},
                json=payload,
            )
        except Exception as e:
            raise AuthServiceRequestError(f"Request KEK failed: {e}")
