from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, Union, List
from datetime import datetime

class HKBConnectionRecord(BaseModel):
    uuid: str # system_id
    endpoint: Optional[str] = None
    connection_type: str = "hkb"
    key: Optional[str] = None # API Key
    user_id: int # external_id
    app_name: Optional[str] = None # name from system_connection
    app_info: Optional[str] = None # raw JSON from system_connection
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True

class HKBAuthResponse(BaseModel):
    success: bool
    status: Optional[Union[str, bool]] = None
    message: Optional[Union[str, Dict[str, Any]]] = None
    data: Optional[Union[Dict[str, Any], List[Any]]] = None
    status_code: Optional[int] = None
