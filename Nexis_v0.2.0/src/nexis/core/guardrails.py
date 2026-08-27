from __future__ import annotations

"""Safety policy for Nexis intrusive-lab workflows.

This module only authorises work against targets explicitly registered by the
operator. It does not perform scans, exploitation, credential attacks, or
shell creation itself.
"""

from dataclasses import dataclass
from ipaddress import ip_address, IPv4Address, IPv6Address
from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets
import time

APP_DIR = Path.home() / ".nexis"
POLICY_FILE = APP_DIR / "lab_policy.json"
SESSION_FILE = APP_DIR / "lab_session.json"

DEFAULT_MAX_CONCURRENT = 4
DEFAULT_SESSION_MINUTES = 30
DEFAULT_CONFIRMATION_REQUIRED = True


@dataclass(frozen=True)
class LabTarget:
    target: str
    label: str
    kind: str = "ctf"
    enabled: bool = True


def _ensure_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def _load() -> dict:
    if not POLICY_FILE.exists():
        return {
            "version": 1,
            "targets": [],
            "admin": {"salt": "", "digest": ""},
            "limits": {
                "max_concurrent": DEFAULT_MAX_CONCURRENT,
                "session_minutes": DEFAULT_SESSION_MINUTES,
                "confirmation_required": DEFAULT_CONFIRMATION_REQUIRED,
            },
        }
    try:
        return json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "version": 1,
            "targets": [],
            "admin": {"salt": "", "digest": ""},
            "limits": {
                "max_concurrent": DEFAULT_MAX_CONCURRENT,
                "session_minutes": DEFAULT_SESSION_MINUTES,
                "confirmation_required": DEFAULT_CONFIRMATION_REQUIRED,
            },
        }


def save_policy(policy: dict) -> None:
    _ensure_dir()
    POLICY_FILE.write_text(json.dumps(policy, indent=2), encoding="utf-8")


def init_policy() -> dict:
    policy = _load()
    if not policy.get("admin", {}).get("digest"):
        password = os.environ.get("NEXIS_ADMIN_PASSWORD")
        if password:
            set_admin_password(password, policy)
            save_policy(policy)
            return {"initialized": True, "password_source": "environment", "warning": "Use a secret manager or OS credential store for production use."}
    return {"initialized": bool(policy.get("admin", {}).get("digest")), "target_count": len(policy.get("targets", []))}


def _digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000, dklen=32)


def set_admin_password(password: str, policy: dict | None = None) -> None:
    if not password or len(password) < 12:
        raise ValueError("Admin password must be at least 12 characters.")
    policy = policy or _load()
    salt = secrets.token_bytes(16)
    policy.setdefault("admin", {})["salt"] = salt.hex()
    policy["admin"]["digest"] = _digest(password, salt).hex()


def verify_admin_password(password: str) -> bool:
    policy = _load()
    admin = policy.get("admin", {})
    if not admin.get("salt") or not admin.get("digest"):
        return False
    try:
        salt = bytes.fromhex(admin["salt"])
        expected = bytes.fromhex(admin["digest"])
    except ValueError:
        return False
    return hmac.compare_digest(_digest(password, salt), expected)


def register_target(target: str, label: str, kind: str = "ctf") -> dict:
    target = target.strip()
    if not target:
        raise ValueError("Target is required.")
    # Lab targets may be IPs or hostnames, but only explicitly registered
    # targets can pass authorization checks later.
    try:
        parsed = ip_address(target)
        if isinstance(parsed, (IPv4Address, IPv6Address)) and not (parsed.is_private or parsed.is_loopback):
            raise ValueError("Only private/loopback IPs can be registered as lab targets.")
    except ValueError as exc:
        if "Only private/loopback" in str(exc):
            raise
        if "." not in target and ":" not in target:
            raise ValueError("Use a valid private IP or hostname.")

    policy = _load()
    targets = policy.setdefault("targets", [])
    for item in targets:
        if item.get("target") == target:
            item.update({"label": label, "kind": kind, "enabled": True})
            save_policy(policy)
            return item
    entry = {"target": target, "label": label, "kind": kind, "enabled": True, "registered_at": int(time.time())}
    targets.append(entry)
    save_policy(policy)
    return entry


def list_targets() -> list[dict]:
    return list(_load().get("targets", []))


def authorize_target(target: str, admin_password: str) -> dict:
    if not verify_admin_password(admin_password):
        raise PermissionError("Admin authorization failed.")
    for entry in list_targets():
        if entry.get("target") == target and entry.get("enabled", False):
            limits = _load().get("limits", {})
            session = {
                "target": target,
                "authorized_at": int(time.time()),
                "expires_at": int(time.time()) + int(limits.get("session_minutes", DEFAULT_SESSION_MINUTES)) * 60,
                "confirmation_required": bool(limits.get("confirmation_required", True)),
            }
            _ensure_dir()
            SESSION_FILE.write_text(json.dumps(session, indent=2), encoding="utf-8")
            return {"authorized": True, "target": target, "expires_at": session["expires_at"], "confirmation_required": session["confirmation_required"]}
    raise PermissionError("Target is not registered in the Nexis lab allowlist.")


def session_status() -> dict:
    if not SESSION_FILE.exists():
        return {"authorized": False}
    try:
        session = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"authorized": False}
    now = int(time.time())
    if now >= int(session.get("expires_at", 0)):
        return {"authorized": False, "expired": True, "target": session.get("target", "")}
    return {"authorized": True, "target": session.get("target", ""), "expires_at": session.get("expires_at"), "confirmation_required": session.get("confirmation_required", True)}


def clear_session() -> None:
    try:
        SESSION_FILE.unlink()
    except FileNotFoundError:
        pass


def policy_status() -> dict:
    policy = _load()
    return {
        "allowlist_only": True,
        "registered_targets": len(policy.get("targets", [])),
        "max_concurrent": int(policy.get("limits", {}).get("max_concurrent", DEFAULT_MAX_CONCURRENT)),
        "session_minutes": int(policy.get("limits", {}).get("session_minutes", DEFAULT_SESSION_MINUTES)),
        "confirmation_required": bool(policy.get("limits", {}).get("confirmation_required", True)),
        "admin_configured": bool(policy.get("admin", {}).get("digest")),
        "session": session_status(),
        "intrusive_execution": False,
    }
