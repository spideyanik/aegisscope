from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any


DEFAULT_ITERATIONS = 600_000


def policy_path() -> Path:
    override = os.environ.get("AEGISSCOPE_OWNER_POLICY")
    if override:
        return Path(override).expanduser()
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "aegisscope" / "owner-policy.json"


def _derive(code: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, iterations)


def create_policy(
    code: str,
    path: str | Path | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> Path:
    if len(code) < 3:
        raise ValueError("owner access code must contain at least 3 characters")
    destination = Path(path) if path else policy_path()
    if destination.exists():
        raise ValueError(f"owner policy already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(16)
    digest = _derive(code, salt, iterations)
    policy: dict[str, Any] = {
        "version": 1,
        "algorithm": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
    }
    destination.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination


def verify_code(code: str, path: str | Path | None = None) -> bool:
    source = Path(path) if path else policy_path()
    if not source.exists():
        raise ValueError(
            "owner authorization is not configured; run 'aegisscope owner-setup' first"
        )
    try:
        policy = json.loads(source.read_text(encoding="utf-8"))
        if policy.get("algorithm") != "pbkdf2-sha256":
            raise ValueError("unsupported owner policy algorithm")
        salt = base64.b64decode(policy["salt"], validate=True)
        expected = base64.b64decode(policy["digest"], validate=True)
        actual = _derive(code, salt, int(policy["iterations"]))
    except (KeyError, TypeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("owner policy is invalid or corrupted") from error
    return secrets.compare_digest(actual, expected)


def setup_owner_policy() -> Path:
    try:
        code = getpass.getpass("Create owner access code: ")
        confirmation = getpass.getpass("Confirm owner access code: ")
    except (EOFError, KeyboardInterrupt) as error:
        raise ValueError("owner setup cancelled") from error
    if code != confirmation:
        raise ValueError("access-code confirmation did not match")
    return create_policy(code)


def require_owner_authorization() -> None:
    try:
        code = getpass.getpass("Owner authorization code: ")
    except (EOFError, KeyboardInterrupt) as error:
        raise ValueError("authorization check cancelled") from error
    if not verify_code(code):
        raise ValueError("authorization denied: owner access code did not match")
    print("Authorization accepted. Scope controls remain enforced.\n")
