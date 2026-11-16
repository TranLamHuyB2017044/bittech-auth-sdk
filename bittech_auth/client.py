import os
import json
import httpx
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union
from .license import load_license_seed
from .security import create_request_metadata
from .exceptions import AuthServiceRequestError

logger = logging.getLogger("bittech_auth")


def _format_error_detail(error_detail: Any) -> str:
    """
    Recursively decodes embedded JSON strings (with Unicode escapes) and returns
    a human-readable UTF-8 JSON string.
    """
    def _decode(val: Any) -> Any:
        if isinstance(val, dict):
            return {k: _decode(v) for k, v in val.items()}
        if isinstance(val, list):
            return [_decode(v) for v in val]
        if isinstance(val, str):
            stripped = val.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (
                stripped.startswith("[") and stripped.endswith("]")
            ):
                try:
                    return _decode(json.loads(stripped))
                except Exception:
                    pass
            if "\\u" in val:
                try:
                    return val.encode("utf-8").decode("unicode_escape")
                except Exception:
                    pass
        return val

    decoded = _decode(error_detail)
    if isinstance(decoded, (dict, list)):
        return json.dumps(decoded, ensure_ascii=False, indent=2)
    return str(decoded)


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
                    error_detail = _format_error_detail(response.json())
                except Exception:
                    error_detail = _format_error_detail(response.text)
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
                    error_detail = _format_error_detail(response.json())
                except Exception:
                    error_detail = _format_error_detail(response.text)
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
        system_connection_id: int = 12,
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
                        "system_connection_id": str(system_connection_id),
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
        license_seed: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verifies the validity of the current license.
        """
        try:
            seed = license_seed
            if not seed and self.license_config_path and self.license_config_path.exists():
                seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "license_key": license_key,
                "license_seed": seed or "",
                "system_id": self.system_id,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": signature or "",
            }
            print(f"verify_license payload: {payload}")
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
        license_seed: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves system connection details from the AuthService.
        """
        try:
            seed = license_seed
            if not seed and self.license_config_path and self.license_config_path.exists():
                seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "source_system_id": self.system_id,
                "group_key": group_keys,
                "client_register": client_register,
                "license_key": license_key or "",
                "license_seed": seed or "",
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
        license_seed: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Registers a new client under the current system.
        """
        try:
            seed = license_seed
            if not seed and self.license_config_path and self.license_config_path.exists():
                seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "system_connection_id": int(connection_id),
                "target_system_id": str(target_system_id),
                "source_system_id": str(self.system_id),
                "external_id": str(external_id),
                "description": str(description or ""),
                "license_key": str(license_key or ""),
                "license_seed": str(seed or ""),
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": str(signature or ""),
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
        target_system_id: Optional[str] = None,
        license_seed: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Authenticates a user and retrieves an access token.
        """
        try:
            seed = license_seed
            if not seed and self.license_config_path and self.license_config_path.exists():
                seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "source_system_id": str(self.system_id),
                "target_system_id": str(target_system_id or ""),
                "license_key": str(license_key or ""),
                "license_seed": str(seed or ""),
                "api_key": str(api_key),
                "user_id": user_id,
                "nonce": metadata["nonce"],
                "timestamp": metadata["timestamp"],
                "signature": str(signature or ""),
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
            seed, _ = load_license_seed(self.license_config_path)
            metadata = create_request_metadata()
            payload = {
                "source_system_id": self.system_id,
                "license_key": license_key or "",
                "license_seed": seed,
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
