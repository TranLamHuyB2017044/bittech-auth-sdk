# bittech-auth-sdk
Bittech Auth Service

- `src/services/hkb_service.py`: Adapter kết nối với SDK HKB (GitHub).

---

## 🔐 Tích hợp HKB Auth SDK

Dự án hiện đang sử dụng **BitTech Auth SDK** được cài đặt trực tiếp từ GitHub để quản lý các kết nối hệ thống bên ngoài (HKB).

### 1. Cài đặt & Cập nhật
Thư viện được quản lý trong `requirements.txt`. Để cài đặt hoặc cập nhật phiên bản mới nhất từ SDK, hãy chạy:
```bash
pip install --upgrade git+https://github.com/TranLamHuyB2017044/bittech-auth-sdk.git
```

### 2. Cách sử dụng trong Backend
SDK đã được bọc lại trong `src/services/hkb_service.py` để hỗ trợ chạy đồng bộ (Synchronous) trong Flask.

```python
from src.services.hkb_service import hkb_service

# Ví dụ Register Client
result = hkb_service.register_client(
    system_connection_id=1,
    system_id="my_system",
    system_register="ocr_module",
    external_id=100,
    description="Mo ta",
    user_info={"email": "example@bittech.vn"}
)

# Ví dụ Authenticate
auth = hkb_service.authenticate(system_id="my_system", api_key="ak_xxx", user_id=100)
```
