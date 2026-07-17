# BitTech Auth Service SDK (Python)

SDK kết nối hệ thống và quản lý bản quyền (License), xác thực (Authentication), chống Replay Attack và quản lý khóa mã hóa (KEK) cho các backend Python tích hợp với **Bittech AuthService**.

---

## 🔐 1. Hướng dẫn Cài đặt

Thư viện có thể cài đặt trực tiếp từ Git repository thông qua `pip` hoặc khai báo trong `requirements.txt`.

### Cài đặt qua Command Line:
```bash
pip install --upgrade git+https://github.com/TranLamHuyB2017044/bittech-auth-sdk.git
```

### Khai báo trong `requirements.txt`:
Để cố định phiên bản hoạt động ổn định trong dự án backend của bạn:
```text
bittech-auth-service @ git+https://github.com/TranLamHuyB2017044/bittech-auth-sdk.git@main
```

---

## 🏗️ 2. Các thành phần chính của SDK

Thư viện export các đối tượng sau từ gói `bittech_auth`:

*   **`AuthServiceClient`**: Client gửi request HTTP đến các endpoint của AuthService. Nhận vào một `HttpTransport`.
*   **`AuthService`**: Lớp dịch vụ điều phối cao cấp (Orchestrator) kết hợp client với repositories lưu trữ nội bộ.
*   **`HttpxTransport`**: Lớp thực thi HTTP Transport đồng bộ mặc định (sử dụng thư viện `httpx`).
*   **`LicenseRepository`**, **`AuditRepository`**, **`NonceStore`**: Các Protocol interface để dự án backend tự định nghĩa lưu trữ (như MongoDB, PostgreSQL, Redis, v.v.).
*   **`encrypt_data`**, **`decrypt_data`**: Các hàm mã hóa và giải mã dữ liệu bằng thuật toán **AES-256-GCM**.

---

## 💻 3. Hướng dẫn Sử dụng

Dưới đây là ví dụ hoàn chỉnh về cách cấu hình Repositories và sử dụng lớp điều phối `AuthService` trong dự án Python của bạn.

### Bước 1: Hiện thực hóa các Repository Protocols của dự án bạn

Dự án backend sử dụng SDK phải tự hiện thực hóa lưu trữ database cho License và Logs. Ví dụ:

```python
from datetime import datetime
from typing import Any, Optional

class MyLicenseRepository:
    def __init__(self):
        # Giả lập database lưu trữ trong RAM
        self.db = {}

    def find_latest(self) -> Optional[dict]:
        if not self.db:
            return None
        # Trả về bản ghi mới nhất
        return list(self.db.values())[-1]

    def find_active(self, now: datetime) -> Optional[dict]:
        latest = self.find_latest()
        if latest and latest.get("status") == 1:
            return latest
        return None

    def save_pending(
        self,
        *,
        public_id: str,
        license_key: str,
        signature: Optional[str],
        expired_at: datetime,
        notes: Optional[str],
        connection_id: int = 12,
    ) -> dict:
        record = {
            "public_id": public_id,
            "license_key": license_key,
            "signature": signature,
            "expired_at": expired_at,
            "status": 0,  # Chờ xác thực ban đầu (status=0)
            "notes": notes,
            "connection_id": connection_id,
        }
        self.db[license_key] = record
        return record

    def mark_verified(self, license_key: str, verified_at: datetime) -> None:
        if license_key in self.db:
            self.db[license_key]["status"] = 1  # Kích hoạt bản quyền
            self.db[license_key]["verified_at"] = verified_at


class MyAuditRepository:
    def log(self, *, action: str, **kwargs) -> None:
        print(f"[AUDIT LOG] Action: {action} | Details: {kwargs}")
```

### Bước 2: Tích hợp và Gọi các nghiệp vụ AuthService

```python
from bittech_auth import AuthServiceClient, HttpxTransport, AuthService

# 1. Khởi tạo transport và client
transport = HttpxTransport()
client = AuthServiceClient(
    system_id="ocr_service_backend",
    license_config_path="path/to/license_config.json",
    transport=transport
)

# 2. Khởi tạo dịch vụ điều phối
licenses_repo = MyLicenseRepository()
audits_repo = MyAuditRepository()

auth_service = AuthService(
    client=client,
    licenses=licenses_repo,
    audits=audits_repo
)

# ==========================================
# CÁC KỊCH BẢN NGHIỆP VỤ CHÍNH
# ==========================================

# A. Đăng ký bản quyền mới (Register License)
# Đọc file config license, tính seed, đẩy lên AuthService và lưu trạng thái chờ vào DB
register_res = auth_service.register_license(
    label="Bản quyền OCR năm 2026",
    expired_at="2027-07-17T00:00:00Z",
    connection_id=12  # Giá trị mặc định là 12
)
print("Đăng ký thành công license_key:", register_res.get("license_key"))

# B. Xác thực kích hoạt bản quyền (Verify License)
# Lấy bản quyền chờ trong DB gửi lên AuthService xác nhận chữ ký và kích hoạt sang status=1
verify_res = auth_service.verify_license()
print("Xác thực bản quyền thành công. Dữ liệu:", verify_res)

# C. Lấy các kết nối được phép (Yêu cầu bản quyền phải Active)
connections = auth_service.get_system_connections(
    group_keys="ocr_group",
    client_register=["ocr_module"]
)
print("Các kết nối được phép:", connections)

# E. Đăng ký người dùng client (Register Client)
client_data = auth_service.register_client(
    connection_id=1,
    target_system_id="hkb_partner_sys",
    external_id="user_id_100",
    description="Nhân viên OCR Module"
)

# F. Xác thực API Key lấy Access Token
token_data = auth_service.authenticate(
    api_key="ak_xxxxxx",
    user_id="user_id_100"
)
access_token = token_data.get("access_token")

# G. Xác minh Access Token hợp lệ
auth_context = auth_service.verify_token(token=access_token)
print("Thông tin xác thực token:", auth_context)

# H. Yêu cầu mã khóa KEK (Key Encryption Key)
kek_info = auth_service.request_kek()
print("Thông tin KEK:", kek_info)
```

---

## 🔒 4. Mã hóa & Giải mã dữ liệu (AES-256-GCM)

Để bảo vệ các gói tin trao đổi với bên thứ 3 theo chuẩn mã hóa của AuthService, sử dụng module `crypto`:

```python
from bittech_auth.crypto import encrypt_data, decrypt_data, generate_random_key

# 1. Sinh một khóa mã hóa ngẫu nhiên 32-byte (dạng hex string)
key = generate_random_key()

secret_data = '{"user_id": 100, "identity_number": "123456789"}'

# 2. Mã hóa dữ liệu (Kết quả là chuỗi Base64 gồm: IV (12B) + Ciphertext + Tag (16B))
ciphertext = encrypt_data(key=key, data=secret_data)
print("Bản mã (Base64):", ciphertext)

# 3. Giải mã dữ liệu
decrypted_data = decrypt_data(key=key, encrypted_str=ciphertext)
print("Dữ liệu giải mã thành công:", decrypted_data)
```
