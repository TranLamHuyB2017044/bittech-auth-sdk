import json
import hashlib
from pathlib import Path
from typing import Any, Tuple
from .exceptions import LicenseConfigError


def canonical_json_stringify(value: Any) -> str:
    """
    Serializes a Python object to canonical JSON string format.
    Ensures keys are sorted, separators are minimal, and Unicode is preserved.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256(value: str) -> str:
    """
    Returns the SHA-256 hash of a string in hexadecimal format.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def calculate_license_seed(config: dict) -> str:
    """
    Calculates the license seed from a license config dictionary.
    """
    return sha256(canonical_json_stringify(config))


def load_license_config(path: str | Path) -> dict:
    """
    Loads and parses a license configuration file.
    Raises LicenseConfigError if loading or parsing fails.
    """
    try:
        file_path = Path(path)
        if not file_path.exists():
            raise LicenseConfigError(f"License file not found at: {file_path}")
            
        with file_path.open("r", encoding="utf-8") as file:
            value = json.load(file)
            
        if not isinstance(value, dict):
            raise LicenseConfigError("License config must be a JSON object")
            
        return value
    except json.JSONDecodeError as e:
        raise LicenseConfigError(f"Invalid JSON format in license config: {e}")
    except LicenseConfigError:
        raise
    except Exception as e:
        raise LicenseConfigError(f"Failed to load license config: {e}")


def load_license_seed(path: str | Path) -> Tuple[str, dict]:
    """
    Loads the license configuration and calculates its seed.
    """
    config = load_license_config(path)
    return calculate_license_seed(config), config
