from __future__ import annotations

from mock_ministry.mocks.protocol_ministry_platform.assertions import evaluate_records
from mock_ministry.mocks.protocol_ministry_platform.evidence import EvidenceRecord


def _record(path="/ministry/receive", subtype=301, ok=True, errors=(), warnings=()):
    return EvidenceRecord(
        raw={},
        method="POST",
        path=path,
        body="{}",
        order_id=f"2-{subtype}-2026070300000000001" if subtype is not None else None,
        sub_type=subtype,
        validation_ok=ok,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def test_observe_mode_accepts_legacy_file_path_as_warning() -> None:
    report = evaluate_records(
        [_record(path="/api/v1/platformFileUpload", subtype=None, warnings=("legacy file path",))],
        mode="observe",
    )

    assert report.ok is True
    assert report.failures == []
    assert any("legacy" in warning for warning in report.warnings)


def test_contract_mode_rejects_legacy_file_path() -> None:
    report = evaluate_records(
        [_record(path="/api/v1/platformFileUpload", subtype=None, warnings=("legacy file path",))],
        mode="contract",
    )

    assert report.ok is False
    assert any("/api/v1/platformFileUpload" in failure for failure in report.failures)


def test_contract_mode_requires_known_receive_subtype() -> None:
    report = evaluate_records([_record(path="/ministry/receive", subtype=999)], mode="contract")

    assert report.ok is False
    assert any("999" in failure for failure in report.failures)


def test_observe_mode_fails_when_no_records_exist() -> None:
    report = evaluate_records([], mode="observe")

    assert report.ok is False
    assert report.failures == ["没有发现 mock evidence 记录"]


def test_contract_mode_accepts_known_receive_subtype() -> None:
    report = evaluate_records([_record(path="/ministry/receive", subtype=301)], mode="contract")

    assert report.ok is True
    assert report.failures == []
