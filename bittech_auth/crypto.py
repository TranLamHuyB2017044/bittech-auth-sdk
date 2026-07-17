import os
import base64
from typing import Union, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _parse_key(key: Union[str, bytes]) -> bytes:
    """
    Converts key to bytes. Handles 64-character hex strings or raw bytes/strings.
    """
    if isinstance(key, bytes):
        return key
    if len(key) == 64:
        try:
            return bytes.fromhex(key)
        except ValueError:
            pass
    return key.encode("utf-8")


def generate_random_key() -> str:
    """
    Generates a random 32-byte key encoded as a hex string.
    """
    return os.urandom(32).hex()


def encrypt_data(key: Union[str, bytes], data: str, associated_data: Optional[bytes] = None) -> str:
    """
    Encrypts a string using AES-256-GCM.
    Returns a Base64-encoded string containing IV (12 bytes) + Ciphertext + Tag (16 bytes).
    """
    key_bytes = _parse_key(key)
    aesgcm = AESGCM(key_bytes)
    iv = os.urandom(12)
    
    ciphertext_with_tag = aesgcm.encrypt(iv, data.encode("utf-8"), associated_data)
    # cryptography package's AESGCM returns ciphertext + tag appended.
    # Therefore, iv + ciphertext_with_tag is IV + Ciphertext + Tag.
    return base64.b64encode(iv + ciphertext_with_tag).decode("utf-8")


def decrypt_data(key: Union[str, bytes], encrypted_str: str, associated_data: Optional[bytes] = None) -> str:
    """
    Decrypts a Base64-encoded string formatted as IV (12 bytes) + Ciphertext + Tag (16 bytes) using AES-256-GCM.
    """
    key_bytes = _parse_key(key)
    raw_data = base64.b64decode(encrypted_str)
    
    if len(raw_data) < 28: # 12 bytes IV + 16 bytes Tag
        raise ValueError("Encrypted data is too short")
        
    iv = raw_data[:12]
    ciphertext_with_tag = raw_data[12:]
    
    aesgcm = AESGCM(key_bytes)
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)
    return decrypted_bytes.decode("utf-8")
