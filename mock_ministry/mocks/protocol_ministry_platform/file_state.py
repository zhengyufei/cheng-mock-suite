"""Durable file-chunk state for real multipart mock requests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .contracts import (
    PROTOCOL_FILE_MAX_ARCHIVE_MEMBERS,
    PROTOCOL_FILE_MAX_CHUNK_BYTES,
    PROTOCOL_FILE_MAX_CHUNKS,
    PROTOCOL_FILE_MAX_EXTRACTED_BYTES,
    PROTOCOL_FILE_MAX_MEMBER_BYTES,
    PROTOCOL_FILE_MAX_TRANSFER_BYTES,
)

from .payloads import (
    SYSTEM_VULNERABILITY_KEYS,
    _validate_system_vulnerability,
    validate_password_dictionary,
)


def _extended_windows_path(path: Path) -> Path:
    """Windows 长路径统一走扩展路径，协议证据仍保留原文件名。"""
    resolved = path.resolve()
    if os.name != "nt":
        return resolved
    value = str(resolved)
    if value.startswith("\\\\?\\"):
        return resolved
    if value.startswith("\\\\"):
        return Path(f"\\\\?\\UNC\\{value[2:]}")
    return Path(f"\\\\?\\{value}")


def _normalize_tar_member_name(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    raw_parts = normalized.split("/")
    windows_path = PureWindowsPath(name)
    member_path = PurePosixPath(normalized)
    has_drive_segment = any(
        len(part) == 2 and part[0].isalpha() and part[1] == ":"
        for part in raw_parts
    )
    if (
        not name
        or "\0" in name
        or member_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or normalized.startswith("//")
        or ".." in raw_parts
        or has_drive_segment
    ):
        raise ValueError("archive contains unsafe path")
    return member_path


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class FileStateResult:
    received_chunks: tuple[int, ...]
    unpack_status: str
    unpack_message: str
    internal_files: tuple[str, ...]
    business_contents: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class FileResourceLimits:
    max_chunks: int = PROTOCOL_FILE_MAX_CHUNKS
    max_chunk_bytes: int = PROTOCOL_FILE_MAX_CHUNK_BYTES
    max_transfer_bytes: int = PROTOCOL_FILE_MAX_TRANSFER_BYTES
    max_tar_members: int = PROTOCOL_FILE_MAX_ARCHIVE_MEMBERS
    max_member_bytes: int = PROTOCOL_FILE_MAX_MEMBER_BYTES
    max_total_decompressed_bytes: int = PROTOCOL_FILE_MAX_EXTRACTED_BYTES
    max_compression_ratio: float = 100.0

    def __post_init__(self) -> None:
        values = (
            self.max_chunks,
            self.max_chunk_bytes,
            self.max_transfer_bytes,
            self.max_tar_members,
            self.max_member_bytes,
            self.max_total_decompressed_bytes,
            self.max_compression_ratio,
        )
        if any(not isinstance(value, (int, float)) or value <= 0 for value in values):
            raise ValueError("file resource limits must be positive")


class FileTransferStateStore:
    def __init__(
        self,
        base_dir: str | Path,
        *,
        limits: FileResourceLimits | None = None,
    ) -> None:
        self.base_dir = _extended_windows_path(Path(base_dir))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.limits = limits or FileResourceLimits()
        self._lock = threading.Lock()

    def _transfer_dir(self, order_id: str, file_id: str) -> Path:
        digest = hashlib.sha256(f"{order_id}\0{file_id}".encode("utf-8")).hexdigest()[:24]
        return self.base_dir / digest

    @staticmethod
    def _result(state: dict) -> FileStateResult:
        return FileStateResult(
            received_chunks=tuple(state["receivedChunks"]),
            unpack_status=state["unpackStatus"],
            unpack_message=state["unpackMessage"],
            internal_files=tuple(state.get("internalFiles", [])),
            business_contents=tuple(state.get("businessContents", [])),
        )

    @staticmethod
    def _write_state(path: Path, state: dict) -> None:
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(path)

    @staticmethod
    def _remove_payloads(transfer_dir: Path) -> None:
        for directory_name in ("chunks", "unpacked"):
            directory = transfer_dir / directory_name
            if directory.exists():
                shutil.rmtree(directory)
        (transfer_dir / "assembled.tar.gz").unlink(missing_ok=True)
        for partial in transfer_dir.glob("*.part"):
            partial.unlink()

    def _finish_terminal_failure(
        self,
        *,
        transfer_dir: Path,
        state_path: Path,
        state: dict,
        status: str,
        message: str,
        failed_chunk_digest: str | None = None,
        clear_received_chunks: bool = False,
    ) -> FileStateResult:
        retained_bytes = int(state.get("receivedBytes", 0))
        state["discardedBytes"] = int(state.get("discardedBytes", 0)) + retained_bytes
        state["receivedBytes"] = 0
        state["unpackStatus"] = status
        state["unpackMessage"] = message
        state["internalFiles"] = []
        state["businessContents"] = []
        if failed_chunk_digest is not None:
            state["failedChunkSha256"] = failed_chunk_digest
        if clear_received_chunks:
            state["receivedChunks"] = []
        self._remove_payloads(transfer_dir)
        self._write_state(state_path, state)
        return self._result(state)

    def fail_transfer(
        self,
        *,
        order_id: str,
        file_id: str,
        message: str,
    ) -> FileStateResult:
        with self._lock:
            transfer_dir = self._transfer_dir(order_id, file_id)
            state_path = transfer_dir / "state.json"
            if not state_path.is_file():
                raise ValueError(f"file transfer state does not exist: {order_id}/{file_id}")
            state = json.loads(state_path.read_text(encoding="utf-8"))
            return self._finish_terminal_failure(
                transfer_dir=transfer_dir,
                state_path=state_path,
                state=state,
                status="failed",
                message=message,
            )

    def reset_transfer(self, *, order_id: str, file_id: str | None = None) -> int:
        """清理指定部侧文件指令的 Mock 状态，供人工重试重新传输。"""
        with self._lock:
            candidates = (
                [self._transfer_dir(order_id, file_id)]
                if file_id is not None
                else list(self.base_dir.iterdir())
            )
            removed = 0
            for transfer_dir in candidates:
                state_path = transfer_dir / "state.json"
                if not state_path.is_file():
                    continue
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if state.get("orderID") != order_id:
                    continue
                if file_id is not None and state.get("fileID") != file_id:
                    continue
                shutil.rmtree(transfer_dir)
                removed += 1
            return removed

    def accept_chunk(
        self,
        *,
        order_id: str,
        file_id: str,
        business_file_name: str,
        total_chunks: int,
        chunk_id: int,
        plaintext_chunk: bytes,
    ) -> FileStateResult:
        if total_chunks > self.limits.max_chunks:
            return FileStateResult(
                received_chunks=(),
                unpack_status="rejected",
                unpack_message=f"Chunk count exceeds {self.limits.max_chunks}.",
                internal_files=(),
                business_contents=(),
            )
        if len(plaintext_chunk) > self.limits.max_chunk_bytes:
            return FileStateResult(
                received_chunks=(),
                unpack_status="rejected",
                unpack_message=f"Chunk size exceeds {self.limits.max_chunk_bytes} bytes.",
                internal_files=(),
                business_contents=(),
            )
        with self._lock:
            transfer_dir = self._transfer_dir(order_id, file_id)
            transfer_dir.mkdir(parents=True, exist_ok=True)
            chunks_dir = transfer_dir / "chunks"
            state_path = transfer_dir / "state.json"
            if state_path.is_file():
                state = json.loads(state_path.read_text(encoding="utf-8"))
            else:
                state = {
                    "orderID": order_id,
                    "fileID": file_id,
                    "businessFileName": business_file_name,
                    "fileTotalChunk": total_chunks,
                    "receivedChunks": [],
                    "chunkDigests": {},
                    "receivedBytes": 0,
                    "discardedBytes": 0,
                    "unpackStatus": "receiving",
                    "unpackMessage": "Waiting for remaining chunks.",
                    "internalFiles": [],
                    "businessContents": [],
                }

            if state["unpackStatus"] in {"failed", "rejected"}:
                return self._finish_terminal_failure(
                    transfer_dir=transfer_dir,
                    state_path=state_path,
                    state=state,
                    status=state["unpackStatus"],
                    message=state["unpackMessage"],
                )

            state.setdefault(
                "receivedBytes",
                sum(path.stat().st_size for path in chunks_dir.glob("*.part")),
            )
            state.setdefault("discardedBytes", 0)

            if (
                state["fileTotalChunk"] != total_chunks
                or state["businessFileName"] != business_file_name
            ):
                return self._finish_terminal_failure(
                    transfer_dir=transfer_dir,
                    state_path=state_path,
                    state=state,
                    status="failed",
                    message="Chunk metadata conflicts with persisted transfer state.",
                    failed_chunk_digest=hashlib.sha256(plaintext_chunk).hexdigest(),
                )

            digest = hashlib.sha256(plaintext_chunk).hexdigest()
            chunk_key = str(chunk_id)
            prior_digest = state["chunkDigests"].get(chunk_key)
            if prior_digest is not None:
                if prior_digest != digest:
                    return self._finish_terminal_failure(
                        transfer_dir=transfer_dir,
                        state_path=state_path,
                        state=state,
                        status="failed",
                        message="Duplicate chunk content does not match persisted data.",
                        failed_chunk_digest=digest,
                    )
                return self._result(state)

            expected_chunk = len(state["receivedChunks"]) + 1
            if chunk_id != expected_chunk:
                return FileStateResult(
                    received_chunks=tuple(state["receivedChunks"]),
                    unpack_status="rejected",
                    unpack_message=f"Expected chunk {expected_chunk} before chunk {chunk_id}.",
                    internal_files=tuple(state.get("internalFiles", [])),
                    business_contents=tuple(state.get("businessContents", [])),
                )

            cumulative_bytes = state["receivedBytes"] + len(plaintext_chunk)
            if cumulative_bytes > self.limits.max_transfer_bytes:
                return self._finish_terminal_failure(
                    transfer_dir=transfer_dir,
                    state_path=state_path,
                    state=state,
                    status="rejected",
                    message=(
                        "Transfer cumulative bytes exceed "
                        f"{self.limits.max_transfer_bytes}."
                    ),
                    failed_chunk_digest=digest,
                    clear_received_chunks=True,
                )

            chunks_dir.mkdir(parents=True, exist_ok=True)
            (chunks_dir / f"{chunk_id:08d}.part").write_bytes(plaintext_chunk)
            state["chunkDigests"][chunk_key] = digest
            state["receivedChunks"] = sorted([*state["receivedChunks"], chunk_id])
            state["receivedBytes"] = cumulative_bytes

            expected = list(range(1, total_chunks + 1))
            if state["receivedChunks"] == expected:
                archive_path = transfer_dir / "assembled.tar.gz"
                try:
                    with archive_path.open("wb") as output:
                        for current in expected:
                            with (chunks_dir / f"{current:08d}.part").open("rb") as source:
                                shutil.copyfileobj(source, output, length=1024 * 1024)
                    sha256 = hashlib.sha256()
                    md5 = hashlib.md5(usedforsecurity=False)
                    with archive_path.open("rb") as source:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            sha256.update(block)
                            md5.update(block)
                    state["archiveSha256"] = sha256.hexdigest()
                    state["archiveMd5"] = md5.hexdigest()
                    shutil.rmtree(chunks_dir)
                    internal_files, business_contents = self._validate_and_extract_archive(
                        archive_path,
                        expected_root=f"{file_id}_{business_file_name}",
                        unpack_dir=transfer_dir / "unpacked",
                        business_file_name=business_file_name,
                        limits=self.limits,
                    )
                except (OSError, tarfile.TarError, ValueError) as exc:
                    return self._finish_terminal_failure(
                        transfer_dir=transfer_dir,
                        state_path=state_path,
                        state=state,
                        status="failed",
                        message=f"Archive validation failed: {exc}",
                    )
                else:
                    state["unpackStatus"] = "completed"
                    state["unpackMessage"] = "Unpacking completed successfully."
                    state["internalFiles"] = internal_files
                    state["businessContents"] = business_contents
                finally:
                    archive_path.unlink(missing_ok=True)

            self._write_state(state_path, state)
            return self._result(state)

    @staticmethod
    def _validate_and_extract_archive(
        path: Path,
        *,
        expected_root: str,
        unpack_dir: Path,
        business_file_name: str = "",
        limits: FileResourceLimits | None = None,
    ) -> tuple[list[str], list[dict[str, Any]]]:
        active_limits = limits or FileResourceLimits()
        safe_files: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        root_directory_seen = False
        total_decompressed = 0
        with tarfile.open(path, mode="r:gz") as archive:
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > active_limits.max_tar_members:
                    raise ValueError(
                        f"archive member count exceeds {active_limits.max_tar_members}"
                    )
                member_path = _normalize_tar_member_name(member.name)
                if not member_path.parts or member_path.parts[0] != expected_root:
                    raise ValueError(f"top-level directory must be {expected_root}")
                if member_path == PurePosixPath(expected_root):
                    if not member.isdir():
                        raise ValueError("top-level entry must be a directory")
                    root_directory_seen = True
                    continue
                if member.issym() or member.islnk():
                    raise ValueError("archive links are not allowed")
                if member.isfile():
                    if member.size > active_limits.max_member_bytes:
                        raise ValueError(
                            f"archive member size exceeds {active_limits.max_member_bytes} bytes"
                        )
                    total_decompressed += member.size
                    if total_decompressed > active_limits.max_total_decompressed_bytes:
                        raise ValueError(
                            "archive total decompressed bytes exceed "
                            f"{active_limits.max_total_decompressed_bytes}"
                        )
                    safe_files.append((member, PurePosixPath(*member_path.parts[1:])))
                elif not member.isdir():
                    raise ValueError("archive contains unsupported entry type")
            if member_count == 0:
                raise ValueError("archive is empty")
            archive_size = max(path.stat().st_size, 1)
            compression_ratio = total_decompressed / archive_size
            if compression_ratio > active_limits.max_compression_ratio:
                raise ValueError(
                    "archive compression ratio "
                    f"{compression_ratio:.2f} exceeds {active_limits.max_compression_ratio:.2f}"
                )
            if not root_directory_seen:
                raise ValueError("archive top-level directory entry is missing")
            if not safe_files:
                raise ValueError("archive contains no internal files")
            if unpack_dir.exists():
                shutil.rmtree(unpack_dir)
            unpack_dir.mkdir(parents=True)
            unpack_root = unpack_dir.resolve()
            for member, internal_path in safe_files:
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"archive member cannot be read: {internal_path.as_posix()}")
                target = (unpack_root / Path(*internal_path.parts)).resolve()
                if not _is_relative_to(target, unpack_root):
                    raise ValueError("archive contains unsafe path")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ValueError(
                                f"archive member ended early: {internal_path.as_posix()}"
                            )
                        output.write(block)
                        remaining -= len(block)
        internal_files = sorted(internal_path.as_posix() for _, internal_path in safe_files)
        business_contents = _summarize_business_contents(
            unpack_dir,
            internal_files,
            business_file_name=business_file_name,
        )
        return internal_files, business_contents


_PASSWORD_HINTS = ("password", "dictionary", "pwd", "weak-password", "口令", "弱口令")
_LOG_HINTS = ("platform-log", "platform_log", "平台日志")
_LOG_SUPPORT_HINTS = ("log-support", "log_support", "配套数据")
_SYSTEM_VUL_HINTS = ("system-vul", "system_vul", "vulnerabilit", "系统漏洞")


def _decode_json_records(content: bytes, path: str) -> tuple[Any, int | None]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path} business content must be UTF-8") from exc
    starts = [index for index in (text.find("["), text.find("{")) if index >= 0]
    if not starts:
        raise ValueError(f"{path} business content must contain JSON")
    start = min(starts)
    prefix = text[:start].strip()
    if prefix and not prefix.isdigit():
        raise ValueError(f"{path} record count prefix must be an integer")
    try:
        payload = json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} business JSON is invalid") from exc
    return payload, int(prefix) if prefix else None


def _required_row_fields(rows: Any, required: set[str], path: str) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError(f"{path} business JSON must be a record list")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}[{index}] must be an object")
        if missing := required - set(row):
            raise ValueError(f"{path}[{index}] missing protocol fields: {sorted(missing)}")
    return rows


def _summary(
    *,
    file_name: str,
    kind: str,
    rows: list[dict[str, Any]],
    id_field: str,
    protocol_fields: set[str],
    count_prefix: int | None,
) -> dict[str, Any]:
    if count_prefix is not None and count_prefix != len(rows):
        raise ValueError(
            f"{file_name} record count prefix {count_prefix} does not match {len(rows)} records"
        )
    identifiers = [str(row[id_field]) for row in rows]
    if any(not identifier for identifier in identifiers):
        raise ValueError(f"{file_name} {id_field} must be non-empty")
    return {
        "file": file_name,
        "kind": kind,
        "recordCount": len(rows),
        "identifiers": identifiers,
        "protocolFields": sorted(protocol_fields),
    }


def _summarize_log_support(payload: Any, file_name: str, count_prefix: int | None) -> dict[str, Any]:
    if count_prefix is not None:
        raise ValueError(f"{file_name} log support data must not use a count prefix")
    if not isinstance(payload, dict) or set(payload) != {"numLogIDs", "numKeys", "logInfo"}:
        raise ValueError(f"{file_name} log support data must contain numLogIDs/numKeys/logInfo")
    num_log_ids = payload["numLogIDs"]
    num_keys = payload["numKeys"]
    rows = payload["logInfo"]
    if type(num_log_ids) is not int or num_log_ids < 0:
        raise ValueError(f"{file_name} numLogIDs must be a non-negative integer")
    if type(num_keys) is not int or num_keys < 0:
        raise ValueError(f"{file_name} numKeys must be a non-negative integer")
    if not isinstance(rows, list):
        raise ValueError(f"{file_name} logInfo must be a list")

    identifiers: set[str] = set()
    observed_keys = 0
    suffixes = ("-target", "-targetPort", "-onlineAddr")
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not row:
            raise ValueError(f"{file_name} logInfo[{index}] must be a non-empty object")
        for key in row:
            if not isinstance(key, str):
                raise ValueError(f"{file_name} logInfo[{index}] keys must be strings")
            suffix = next((item for item in suffixes if key.endswith(item)), None)
            if suffix is None or not key[: -len(suffix)]:
                raise ValueError(f"{file_name} logInfo[{index}] contains an invalid protocol key")
            identifiers.add(key[: -len(suffix)])
            observed_keys += 1
    if num_keys != observed_keys:
        raise ValueError(f"{file_name} numKeys {num_keys} does not match {observed_keys} keys")
    if num_log_ids != len(identifiers):
        raise ValueError(f"{file_name} numLogIDs {num_log_ids} does not match {len(identifiers)} IDs")
    return {
        "file": file_name,
        "kind": "log_support_data",
        "recordCount": observed_keys,
        "identifiers": sorted(identifiers),
        "protocolFields": ["logInfo", "numKeys", "numLogIDs"],
    }


def _exact_object_keys(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    missing = expected - set(value)
    unexpected = set(value) - expected
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing keys: {sorted(missing)}")
        if unexpected:
            details.append(f"unexpected keys: {sorted(unexpected)}")
        raise ValueError(f"{path} {'; '.join(details)}")
    return value


def _non_negative_count(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{path} must be a non-negative integer")
    return value


def _summarize_system_vulnerabilities(
    payload: Any,
    file_name: str,
    count_prefix: int | None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"{file_name} VulInfoLst must be an object")
    missing = {"vulNum", "comVulLst"} - set(payload)
    unexpected = set(payload) - {"vulNum", "engLst", "comVulLst"}
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing keys: {sorted(missing)}")
        if unexpected:
            details.append(f"unexpected keys: {sorted(unexpected)}")
        raise ValueError(f"{file_name} VulInfoLst {'; '.join(details)}")
    vulnerability_list = payload
    vulnerability_count = _non_negative_count(
        vulnerability_list["vulNum"],
        f"{file_name} VulInfoLst.vulNum",
    )

    if "engLst" in vulnerability_list:
        engineering = _exact_object_keys(
            vulnerability_list["engLst"],
            {"engNum", "engDevs"},
            f"{file_name} VulInfoLst.engLst",
        )
        engineering_count = _non_negative_count(
            engineering["engNum"],
            f"{file_name} VulInfoLst.engLst.engNum",
        )
        devices = engineering["engDevs"]
        if not isinstance(devices, list):
            raise ValueError(f"{file_name} VulInfoLst.engLst.engDevs must be a list")
        if engineering_count != len(devices):
            raise ValueError(
                f"{file_name} VulInfoLst.engLst.engNum {engineering_count} "
                f"does not match {len(devices)} engDevs"
            )
        for index, device_value in enumerate(devices):
            device_path = f"{file_name} VulInfoLst.engLst.engDevs[{index}]"
            device = _exact_object_keys(device_value, {"engHash", "engType"}, device_path)
            if type(device["engHash"]) is not str:
                raise ValueError(f"{device_path}.engHash must be str")
            if type(device["engType"]) is not int:
                raise ValueError(f"{device_path}.engType must be int")

    groups = vulnerability_list["comVulLst"]
    if not isinstance(groups, list):
        raise ValueError(f"{file_name} VulInfoLst.comVulLst must be a list")
    if vulnerability_count != len(groups):
        raise ValueError(
            f"{file_name} VulInfoLst.vulNum {vulnerability_count} "
            f"does not match {len(groups)} comVulLst groups"
        )
    if count_prefix is not None and count_prefix != vulnerability_count:
        raise ValueError(
            f"{file_name} record count prefix {count_prefix} "
            f"does not match VulInfoLst.vulNum {vulnerability_count}"
        )

    instances: list[dict[str, Any]] = []
    for index, group_value in enumerate(groups):
        group_path = f"{file_name} VulInfoLst.comVulLst[{index}]"
        if not isinstance(group_value, dict):
            raise ValueError(f"{group_path} must be an object")
        identifiers = {"vulID", "pwDictInstID"} & set(group_value)
        if len(identifiers) != 1:
            raise ValueError(f"{group_path} must contain exactly one of vulID/pwDictInstID")
        identifier_key = next(iter(identifiers))
        group = _exact_object_keys(
            group_value,
            {identifier_key, "assetNum", "instVulLst"},
            group_path,
        )
        if type(group[identifier_key]) is not str or not group[identifier_key]:
            raise ValueError(f"{group_path}.{identifier_key} must be a non-empty string")
        asset_count = _non_negative_count(group["assetNum"], f"{group_path}.assetNum")
        group_instances = group["instVulLst"]
        if not isinstance(group_instances, list):
            raise ValueError(f"{group_path}.instVulLst must be a list")
        if asset_count != len(group_instances):
            raise ValueError(
                f"{group_path}.assetNum {asset_count} "
                f"does not match {len(group_instances)} instVulLst entries"
            )
        for instance_index, instance in enumerate(group_instances):
            instance_path = f"{group_path}.instVulLst[{instance_index}]"
            errors: list[str] = []
            _validate_system_vulnerability(instance, instance_path, errors)
            if errors:
                raise ValueError(f"{file_name} InstVul invalid: {'; '.join(errors)}")
            instances.append(instance)

    return _summary(
        file_name=file_name,
        kind="system_vulnerability",
        rows=instances,
        id_field="vulInfoID",
        protocol_fields=SYSTEM_VULNERABILITY_KEYS,
        count_prefix=None,
    )


def _summarize_business_contents(
    unpack_dir: Path,
    internal_files: list[str],
    *,
    business_file_name: str,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for internal_file in internal_files:
        hint = f"{business_file_name}/{internal_file}".lower()
        target_hint = any(
            token in hint
            for token in (*_PASSWORD_HINTS, *_LOG_HINTS, *_LOG_SUPPORT_HINTS, *_SYSTEM_VUL_HINTS)
        )
        if not target_hint and not internal_file.lower().endswith(".json"):
            continue
        content_path = unpack_dir / Path(*PurePosixPath(internal_file).parts)
        try:
            payload, count_prefix = _decode_json_records(content_path.read_bytes(), internal_file)
        except ValueError:
            if target_hint:
                raise
            continue

        if isinstance(payload, dict) and {"pwDictNum", "pwLst"} <= set(payload):
            if validation_errors := validate_password_dictionary(payload):
                raise ValueError(f"{internal_file} password dictionary invalid: {'; '.join(validation_errors)}")
            rows = payload["pwLst"]
            if count_prefix is not None:
                raise ValueError(f"{internal_file} password dictionary must not use a count prefix")
            summaries.append(
                _summary(
                    file_name=internal_file,
                    kind="password_dictionary",
                    rows=rows,
                    id_field="pwDictID",
                    protocol_fields={"pwDictID", "pwProto", "pwDTitle", "pwDictType", "pwData"},
                    count_prefix=payload["pwDictNum"],
                )
            )
            continue

        if (
            isinstance(payload, dict)
            and set(payload) == {"numLogIDs", "numKeys", "logInfo"}
        ) or any(token in hint for token in _LOG_SUPPORT_HINTS):
            summaries.append(_summarize_log_support(payload, internal_file, count_prefix))
            continue

        if (
            isinstance(payload, dict)
            and {"vulNum", "engLst", "comVulLst"} <= set(payload)
        ) or any(token in hint for token in _SYSTEM_VUL_HINTS):
            summaries.append(
                _summarize_system_vulnerabilities(payload, internal_file, count_prefix)
            )
            continue

        rows = payload if isinstance(payload, list) else None
        first = rows[0] if rows else {}
        if any(token in hint for token in _LOG_HINTS) or "logID" in first:
            required = {
                "logID", "orderID", "timeStamp", "devHash", "logType", "logLvl", "opCode", "opRslt", "content",
            }
            typed_rows = _required_row_fields(rows, required, internal_file)
            summaries.append(
                _summary(
                    file_name=internal_file,
                    kind="platform_log",
                    rows=typed_rows,
                    id_field="logID",
                    protocol_fields=required,
                    count_prefix=count_prefix,
                )
            )
            continue
        if target_hint:
            raise ValueError(f"{internal_file} does not contain a recognized protocol business structure")
    return summaries
