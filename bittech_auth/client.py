import httpx
import json
import logging
from typing import Optional, List, Dict, Any, Union
from .models import HKBAuthResponse, HKBConnectionRecord

logger = logging.getLogger("bittech_hkb")

class HKBClient:
    def __init__(self, base_url: str = "https://auth.hkbcert.vn"):
        self.base_url = base_url.rstrip("/")
        self._token_cache: Dict[str, Dict[str, Any]] = {}

    async def get_system_connections(
        self, group_key: str, client_registers: List[str]
    ) -> HKBAuthResponse:
        """
        Retrieves available system connections from HKB.
        """
        url = f"{self.base_url}/api/system-connections/get"
        params = {
            "group_key": group_key,
            "client_register": client_registers
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, params=params, timeout=10.0)
                return self._parse_response(response)
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def register_client(
        self,
        system_connection_id: int,
        system_id: str,
        system_register: str,
        external_id: Union[int, str],
        description: str,
        user_info: Union[str, Dict[str, Any]]
    ) -> HKBAuthResponse:
        """
        Registers a user/client with the HKB system.
        """
        url = f"{self.base_url}/api/client-registers"
        
        if isinstance(user_info, dict):
            user_info = json.dumps(user_info, ensure_ascii=False)
            
        payload = {
            "system_connection_id": system_connection_id,
            "system_id": system_id,
            "system_register": system_register,
            "external_id": external_id,
            "description": description,
            "user_info": user_info
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, json=payload, timeout=10.0)
                parsed = self._parse_response(response)
                
                # Auto-authenticate if registration successful
                if parsed.success:
                    await self._handle_auto_auth(parsed, system_id, external_id)
                
                return parsed
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def authenticate(
        self, system_id: str, api_key: str, user_id: int
    ) -> HKBAuthResponse:
        """
        Obtains a Bearer token from HKB using the API Key.
        """
        url = f"{self.base_url}/api/authenticate"
        payload = {
            "system_id": system_id,
            "api_key": api_key,
            "user_id": user_id
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, json=payload, timeout=10.0)
                parsed = self._parse_response(response)
                
                if parsed.success and parsed.data:
                    token = parsed.data.get("access_token")
                    if token:
                        self._token_cache[system_id] = {
                            "token": token,
                            "api_key": api_key,
                            "user_id": user_id
                        }
                return parsed
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def upload_document(
        self, endpoint: str, system_id: str, api_key: str, user_id: int, payload: Dict[str, Any]
    ) -> HKBAuthResponse:
        """
        Uploads/Shares a document with an external endpoint using HKB auth.
        """
        # Get token
        token = await self._get_valid_token(system_id, api_key, user_id)
        if not token:
            return HKBAuthResponse(success=False, message="Failed to obtain authentication token")

        url = f"{endpoint.rstrip('/')}/api/share/car-documents"
        headers = {"Authorization": f"Bearer {token}"}
        body = {
            "authentication": {
                "system_id": system_id,
                "api_key": api_key,
                "user_id": user_id
            },
            "payload": payload
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, json=body, headers=headers, timeout=30.0)
                return self._parse_response(response)
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def _get_valid_token(self, system_id: str, api_key: str, user_id: int) -> Optional[str]:
        cache = self._token_cache.get(system_id)
        if cache and cache.get("token"):
            return cache["token"]
        
        auth_res = await self.authenticate(system_id, api_key, user_id)
        if auth_res.success and auth_res.data:
            return auth_res.data.get("access_token")
        return None

    def _parse_response(self, response: httpx.Response) -> HKBAuthResponse:
        status_code = response.status_code
        try:
            data = response.json()
            is_success = (data.get("success") is True) or (data.get("status") == "success")
            return HKBAuthResponse(
                success=is_success,
                status=data.get("status"),
                message=data.get("message"),
                data=data.get("data"),
                status_code=status_code
            )
        except Exception:
            return HKBAuthResponse(
                success=False,
                message="Invalid JSON response",
                data={"raw": response.text},
                status_code=status_code
            )

    async def _handle_auto_auth(self, parsed: HKBAuthResponse, system_id: str, external_id: Any):
        # Extract API key if available in response
        # (Based on current auth_routes.py complex mapping)
        try:
            data = parsed.data
            if not data: return
            
            # Navigate nested structure
            payload_data = None
            if "api_key" in data:
                payload_data = data
            elif isinstance(data.get("data"), dict) and "api_key" in data["data"]:
                payload_data = data["data"]
            
            if payload_data:
                api_key = payload_data.get("api_key")
                if api_key:
                    await self.authenticate(system_id, api_key, int(external_id))
        except Exception as e:
            logger.warning(f"Auto-auth failed: {e}")
