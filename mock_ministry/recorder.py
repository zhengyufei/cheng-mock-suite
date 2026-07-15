"""File-based request/response recorder for the mock receiver."""

from __future__ import annotations

import json
import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class FileRecorder:
    """Append request/response records to reports/mock-server/<run>/requests.jsonl."""

    def __init__(self, base_dir: str | Path | None = None, run_id: str | None = None) -> None:
        root = Path(base_dir) if base_dir is not None else Path("reports") / "mock-server"
        timestamp = run_id or datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        self.run_dir = root / timestamp
        self.path = self.run_dir / "requests.jsonl"
        self._lock = threading.Lock()
        self._sequence = 0
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str | bytes,
        response: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Path:
        with self._lock:
            self._sequence += 1
            record = {
                "sequence": self._sequence,
                "time": datetime.now(timezone.utc).isoformat(),
                "method": method,
                "path": path,
                "headers": _sanitize(headers),
                "body": _sanitize_body(body, headers),
            }
            if response is not None:
                record["response"] = _sanitize(response)
            if meta is not None:
                record["meta"] = _sanitize(meta)
            line = json.dumps(record, ensure_ascii=False, sort_keys=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return self.path


_SENSITIVE_NAMES = {
    "authorization",
    "cookie",
    "accesstoken",
    "xenckey",
    "xenckeyg",
    "xencnonce",
    "xencauthtag",
    "xencauthtagfile",
    "nonce",
    "authtag",
}


def _redacted(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"[redacted sha256:{digest}]"


def _is_sensitive_name(value: Any) -> bool:
    normalized = "".join(char for char in str(value).lower() if char.isalnum())
    if normalized in _SENSITIVE_NAMES or normalized in {"jwt", "sm", "xenc"}:
        return True
    if any(marker in normalized for marker in ("token", "password", "passwd", "secret", "cookie")):
        return True
    if normalized == "pwd" or normalized.endswith("pwd"):
        return True
    if normalized == "auth" or normalized.startswith("auth") or normalized.endswith("auth"):
        return True
    if normalized.endswith(("privatekey", "publickey")):
        return True
    return "jwt" in normalized or "xenc" in normalized or any(
        marker in normalized
        for marker in (
            "sm2",
            "sm3",
            "sm4",
            "sm9",
            "smkey",
            "smmaterial",
            "smprivate",
            "smpublic",
        )
    )


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redacted(child) if _is_sensitive_name(key) else _sanitize(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(child) for child in value]
    return value


def _sanitize_body(body: str | bytes, headers: dict[str, str]) -> Any:
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    if "multipart/form-data" in content_type.lower():
        raw = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
        preview_bytes = raw[:128]
        preview = "".join(chr(value) if 32 <= value <= 126 else "." for value in preview_bytes)
        return {
            "kind": "multipart/form-data",
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "preview": preview,
            "truncated": len(raw) > len(preview_bytes),
        }
    try:
        parsed = json.loads(body)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        if isinstance(body, bytes):
            return body[:256].decode("utf-8", errors="replace")
        return body[:256]
    return json.dumps(_sanitize(parsed), ensure_ascii=False, separators=(",", ":"))
