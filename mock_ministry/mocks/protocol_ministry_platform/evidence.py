from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class EvidenceRecord:
    raw: dict[str, Any]
    method: str
    path: str
    body: str
    order_id: str | None
    sub_type: int | None
    validation_ok: bool | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def _record_from_raw(raw: dict[str, Any]) -> EvidenceRecord:
    meta = raw.get("meta") or {}
    protocol = meta.get("protocol") or {}
    validation = meta.get("validation") or {}
    sub_type = protocol.get("orderSubType")
    if sub_type is not None:
        sub_type = int(sub_type)

    return EvidenceRecord(
        raw=raw,
        method=str(raw.get("method") or ""),
        path=str(raw.get("path") or ""),
        body=str(raw.get("body") or ""),
        order_id=protocol.get("orderID"),
        sub_type=sub_type,
        validation_ok=validation.get("ok"),
        errors=tuple(str(item) for item in validation.get("errors") or []),
        warnings=tuple(str(item) for item in validation.get("warnings") or []),
    )


def load_records(path: str | Path) -> list[EvidenceRecord]:
    record_path = Path(path)
    records: list[EvidenceRecord] = []
    for line in record_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        if not isinstance(raw, dict):
            raise ValueError(f"record line must be object: {line}")
        records.append(_record_from_raw(raw))
    return records


def latest_run_dir(record_dir: str | Path) -> Path:
    root = Path(record_dir)
    candidates = [path for path in root.iterdir() if path.is_dir() and (path / "requests.jsonl").is_file()]
    if not candidates:
        raise FileNotFoundError(f"no mock evidence run found under {root}")
    return sorted(candidates, key=lambda path: path.name)[-1]


def filter_records(
    records: Iterable[EvidenceRecord],
    *,
    path: str | None = None,
    sub_type: int | None = None,
) -> list[EvidenceRecord]:
    result: list[EvidenceRecord] = []
    for record in records:
        if path is not None and record.path != path:
            continue
        if sub_type is not None and record.sub_type != sub_type:
            continue
        result.append(record)
    return result


def summarize_records(records: Iterable[EvidenceRecord]) -> dict[str, Any]:
    summary: dict[str, Any] = {"total": 0, "paths": {}, "subtypes": {}, "errors": 0, "warnings": 0}
    for record in records:
        summary["total"] += 1
        summary["paths"][record.path] = summary["paths"].get(record.path, 0) + 1
        if record.sub_type is not None:
            key = str(record.sub_type)
            summary["subtypes"][key] = summary["subtypes"].get(key, 0) + 1
        summary["errors"] += len(record.errors)
        summary["warnings"] += len(record.warnings)
    return summary
