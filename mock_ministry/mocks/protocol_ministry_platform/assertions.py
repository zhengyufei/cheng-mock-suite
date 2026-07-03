from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .contracts import (
    KNOWN_PROTOCOL_SUBTYPES,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
    PLATFORM_FILE_PATH,
    PLATFORM_RECEIVE_PATH,
)
from .evidence import EvidenceRecord, summarize_records


@dataclass(frozen=True)
class CheckReport:
    mode: str
    ok: bool
    summary: dict
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "ok": self.ok,
            "summary": self.summary,
            "failures": self.failures,
            "warnings": self.warnings,
        }


def evaluate_records(records: Iterable[EvidenceRecord], *, mode: str) -> CheckReport:
    record_list = list(records)
    if mode not in {"observe", "contract"}:
        raise ValueError("mode must be observe or contract")

    failures: list[str] = []
    warnings: list[str] = []
    summary = summarize_records(record_list)

    if not record_list:
        failures.append("没有发现 mock evidence 记录")
        return CheckReport(mode=mode, ok=False, summary=summary, failures=failures, warnings=warnings)

    for record in record_list:
        if record.validation_ok is False or record.errors:
            failures.append(f"{record.path} envelope validation failed: {'; '.join(record.errors)}")

        if record.path == LEGACY_PLATFORM_FILE_UPLOAD_PATH:
            message = f"当前后端仍在调用 {LEGACY_PLATFORM_FILE_UPLOAD_PATH}；协议目标应评估为 {PLATFORM_FILE_PATH}"
            if mode == "contract":
                failures.append(message)
            else:
                warnings.append(message)

        if record.path == PLATFORM_RECEIVE_PATH and record.sub_type is None:
            failures.append(f"{record.path} 缺少可识别 subtype")

        if record.sub_type is not None and record.sub_type not in KNOWN_PROTOCOL_SUBTYPES:
            failures.append(f"{record.path} 出现未知 subtype {record.sub_type}")

        for warning in record.warnings:
            warnings.append(f"{record.path}: {warning}")

    return CheckReport(mode=mode, ok=not failures, summary=summary, failures=failures, warnings=warnings)
