"""File-based request/response recorder for the mock receiver."""

from __future__ import annotations

import json
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
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str,
        response: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Path:
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
        }
        if response is not None:
            record["response"] = response
        if meta is not None:
            record["meta"] = meta

        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return self.path
