import httpx
import json
from loguru import logger
from typing import Optional, List, Dict, Any, Union
from .models import HKBAuthResponse, HKBConnectionRecord

class HKBClient:
    def __init__(self, base_url: str = "https://auth.hkbcert.vn"):
        self.base_url = base_url.rstrip("/")
        self._token_cache: Dict[str, Dict[str, Any]] = {}

    async def get_system_connections(
        self, group_key: Union[str, List[str]], client_registers: List[str]
    ) -> HKBAuthResponse:
        """
        Retrieves available system connections from HKB.
        
        Args:
            group_key: A single group key or a list of group keys to filter connections.
            client_registers: A list of client register application keys.
        """
        url = f"{self.base_url}/api/system-connections/get"
        payload = {
            "group_key": group_key,
            "client_register": client_registers
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.request("GET", url, json=payload, timeout=10.0)
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
                logger.info(f"HKB Client: Registration Payload: {json.dumps(payload, ensure_ascii=False)}")
                response = await client.post(url, json=payload, timeout=10.0)
                parsed = self._parse_response(response)
                
                # Auto-authenticate if registration successful
                if parsed.success:
                    await self._handle_auto_auth(parsed, system_id, external_id)
                
                return parsed
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def revoke_api_key(
        self,
        system_id: str,
        api_key: str,
        password: str
    ) -> HKBAuthResponse:
        """
        Revokes a system's API key.
        """
        url = f"{self.base_url}/api/client-registers/revoke-api-key"
        payload = {
            "system_id": system_id,
            "api_key": api_key,
            "password": password
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(url, json=payload, timeout=10.0)
                return self._parse_response(response)
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
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
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

    async def get_employees(
        self, url: str, system_id: str, api_key: str, user_id: int
    ) -> HKBAuthResponse:
        """
        Fetches employee list from a specific URL using HKB auth.
        """
        # Get token
        token = await self._get_valid_token(system_id, api_key, user_id)
        if not token:
            return HKBAuthResponse(success=False, message="Failed to obtain authentication token")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        body = {
            "authentication": {
                "system_id": system_id,
                "api_key": api_key,
                "user_id": user_id
            }
        }

        async with httpx.AsyncClient() as client:
            try:
                # Using GET as requested by the user
                response = await client.request("GET", url, json=body, headers=headers, timeout=30.0)
                return self._parse_response(response)
            except Exception as e:
                return HKBAuthResponse(success=False, message=str(e))

    async def get_hr_users(
        self, endpoint: str, system_id: str, api_key: str, user_id: int
    ) -> HKBAuthResponse:
        """
        Fetches HR user list from a specific endpoint. 
        Requested for 'tester' environment.
        """
        # Get token
        token = await self._get_valid_token(system_id, api_key, user_id)
        if not token:
            return HKBAuthResponse(success=False, message="Failed to obtain authentication token")

        url = f"{endpoint.rstrip('/')}/api/hr/users"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        body = {
            "authentication": {
                "system_id": system_id,
                "api_key": api_key,
                "user_id": user_id
            }
        }

        async with httpx.AsyncClient() as client:
            try:
                # Supporting both GET/POST, using GET as requested
                response = await client.request("GET", url, json=body, headers=headers, timeout=30.0)
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
        raw_text = response.text
        try:
            data = response.json()
            is_success = (data.get("success") is True) or (data.get("status") == "success") or (data.get("status") is True)
            return HKBAuthResponse(
                success=is_success,
                status=data.get("status"),
                message=data.get("message"),
                data=data.get("data"),
                status_code=status_code
            )
        except Exception as e:
            # Log the raw text for debugging if JSON parsing fails
            logger.error(f"HKB Client Error: Failed to parse response. Error: {e}")
            logger.error(f"Status: {status_code}")
            logger.error(f"Raw Response Content: {raw_text[:2000]}") 
            
            return HKBAuthResponse(
                success=False,
                message="Invalid JSON response",
                data={"raw": raw_text},
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

    async def upload_timekeepers(
        self, url: str, system_id: str, api_key: str, user_id: int, 
        payload: List[Dict[str, Any]], files: Dict[str, bytes]
    ) -> HKBAuthResponse:
        """
        Uploads attendance timekeepers with images as multipart form data.
        Follows Laravel-style field flattening (e.g. authentication[system_id]).
        """
        # Get token
        token = await self._get_valid_token(system_id, api_key, user_id)
        if not token:
            return HKBAuthResponse(success=False, message="Failed to obtain authentication token")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        
        # Prepare DATA fields (Laravel style flattening)
        body_data = {
            "authentication": {
                "api_key": api_key,
                "system_id": system_id,
                "user_id": int(user_id)
            },
            "payload": payload
        }
        
        flattened_data = self._flatten_multipart_fields(body_data)
        
        # Prepare FILE fields
        files_dict = {}
        for session_id, image_bytes in files.items():
            # Laravel code: ->attach('files[id]', $handle, $filename)
            field_name = f"files[{session_id}]" 
            files_dict[field_name] = (f"{session_id}.webp", image_bytes, "image/webp")

        logger.info(f"HKB Client: POST {url}")
        logger.info(f"HKB Client: Headers: {headers}")
        logger.info(f"HKB Client: FULL Flattened Data: {json.dumps(flattened_data, ensure_ascii=False, indent=2)}")
        logger.info(f"HKB Client: File fields: {list(files_dict.keys())}")
        
        async with httpx.AsyncClient() as client:
            try:
                # 'data' sends flattened fields, 'files' sends multipart files
                response = await client.post(url, headers=headers, data=flattened_data, files=files_dict, timeout=60.0)
                return self._parse_response(response)
            except Exception as e:
                logger.error(f"Upload timekeepers failed: {e}")
                return HKBAuthResponse(success=False, message=str(e))

    def _flatten_multipart_fields(self, data: Any, prefix: str = "") -> Dict[str, str]:
        """
        Converts nested dictionaries/lists into a flat dict of Laravel-style keys.
        """
        out = {}
        if isinstance(data, dict):
            for key, value in data.items():
                name = f"{prefix}[{key}]" if prefix else str(key)
                out.update(self._flatten_multipart_fields(value, name))
        elif isinstance(data, (list, tuple)):
            for i, value in enumerate(data):
                name = f"{prefix}[{i}]"
                out.update(self._flatten_multipart_fields(value, name))
        else:
            if prefix:
                if isinstance(data, bool):
                    out[prefix] = "1" if data else "0"
                else:
                    out[prefix] = str(data) if data is not None else ""
        return out
