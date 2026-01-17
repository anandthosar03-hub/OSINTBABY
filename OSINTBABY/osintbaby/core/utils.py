"""Utility functions for OSINT CLI."""

import yaml
import re
import validators
from pathlib import Path
from typing import Dict, Any, Optional
import ipaddress


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config.yaml"
    
    config_path = Path(config_path)
    
    if not config_path.exists():
        return get_default_config()
    
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_default_config() -> Dict[str, Any]:
    """Return default configuration."""
    return {
        "api_keys": {},
        "settings": {
            "timeout": 30,
            "max_retries": 3,
            "user_agent": "OSINT-CLI/1.0",
            "output_format": "table"
        },
        "rate_limits": {
            "default_delay": 1
        }
    }


def validate_input(input_type: str, value: str) -> bool:
    """Validate input based on type."""
    validators_map = {
        "domain": validate_domain,
        "ip": validate_ip,
        "email": validate_email,
        "username": validate_username,
        "phone": validate_phone,
        "hash": validate_hash,
    }
    
    validator = validators_map.get(input_type)
    if validator:
        return validator(value)
    return False


def validate_domain(domain: str) -> bool:
    """Validate domain name."""
    return validators.domain(domain) is True


def validate_ip(ip: str) -> bool:
    """Validate IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_email(email: str) -> bool:
    """Validate email address."""
    return validators.email(email) is True


def validate_username(username: str) -> bool:
    """Validate username format."""
    pattern = r'^[a-zA-Z0-9_.-]{3,50}$'
    return bool(re.match(pattern, username))


def validate_phone(phone: str) -> bool:
    """Validate phone number."""
    pattern = r'^\+?[1-9]\d{6,14}$'
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    return bool(re.match(pattern, cleaned))


def validate_hash(hash_value: str) -> bool:
    """Validate hash (MD5, SHA1, SHA256)."""
    patterns = {
        "md5": r'^[a-fA-F0-9]{32}$',
        "sha1": r'^[a-fA-F0-9]{40}$',
        "sha256": r'^[a-fA-F0-9]{64}$',
    }
    return any(re.match(p, hash_value) for p in patterns.values())


def get_hash_type(hash_value: str) -> Optional[str]:
    """Determine the type of hash."""
    length_map = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
    }
    return length_map.get(len(hash_value))