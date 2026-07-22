from __future__ import annotations

import hashlib
import http.client
import io
import json
import tarfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from mock_ministry.mocks.protocol_ministry_platform import envelope as envelope_module
from mock_ministry.mocks.protocol_ministry_platform import file_state as file_state_module
from mock_ministry.mocks.protocol_ministry_platform.server import MAX_REQUEST_BYTES, create_server
from mock_ministry.recorder import FileRecorder


def _archive(root: str, members: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, content in members:
            member = tarfile.TarInfo(f"{root}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def _accept(tmp_path, archive: bytes, limits):
    store = file_state_module.FileTransferStateStore(tmp_path / "state", limits=limits)
    return store.accept_chunk(
        order_id="0-0-2026071400000000073",
        file_id="7" * 32,
        business_file_name="bounded.json",
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=archive,
    )


def _payload_files(transfer_dir):
    return [
        path
        for path in transfer_dir.rglob("*")
        if path.is_file() and path.name != "state.json"
    ]


def test_failed_transfer_can_be_reset_by_order_for_a_real_retry(tmp_path) -> None:
    store = file_state_module.FileTransferStateStore(tmp_path / "state")
    order_id = "0-0-2026071400000000099"
    file_id = "9" * 32
    first = store.accept_chunk(
        order_id=order_id,
        file_id=file_id,
        business_file_name="retry.json",
        total_chunks=2,
        chunk_id=1,
        plaintext_chunk=b"first-part",
    )
    assert first.unpack_status == "receiving"
    assert store.fail_transfer(
        order_id=order_id,
        file_id=file_id,
        message="injected failure",
    ).unpack_status == "failed"

    assert store.reset_transfer(order_id=order_id) == 1
    retried = store.accept_chunk(
        order_id=order_id,
        file_id=file_id,
        business_file_name="retry.json",
        total_chunks=2,
        chunk_id=1,
        plaintext_chunk=b"first-part",
    )
    assert retried.unpack_status == "receiving"


def test_platform_log_archive_preserves_chinese_protocol_file_names(tmp_path) -> None:
    platform_logs = json.dumps(
        [
            {
                "logID": "L1",
                "orderID": "2-104-2026071400000000098",
                "timeStamp": "1752500000",
                "devHash": "a" * 64,
                "logType": 1,
                "logLvl": 2,
                "opCode": 1,
                "opRslt": 0,
                "content": "acceptance",
            }
        ],
        ensure_ascii=False,
    ).encode("utf-8")
    support = json.dumps(
        {"numLogIDs": 1, "numKeys": 1, "logInfo": [{"L1-target": "acceptance"}]},
        ensure_ascii=False,
    ).encode("utf-8")
    file_id = "8" * 32
    business_name = "test-data-2026071400000000098-3"
    archive = _archive(
        f"{file_id}_{business_name}",
        [("平台日志文件.json", platform_logs), ("日志配套数据文件.json", support)],
    )

    long_base = tmp_path.joinpath(*(["long-protocol-report-segment"] * 6), "state")
    assert len(str(long_base / ("f" * 64))) > 260
    result = file_state_module.FileTransferStateStore(long_base).accept_chunk(
        order_id="0-0-2026071400000000098",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=archive,
    )

    assert result.unpack_status == "completed", result.unpack_message
    assert [item["kind"] for item in result.business_contents] == [
        "platform_log",
        "log_support_data",
    ]


def test_file_state_rejects_chunk_count_before_allocating_transfer_state(tmp_path) -> None:
    limits_type = getattr(file_state_module, "FileResourceLimits", None)
    assert limits_type is not None, "文件状态需要显式资源预算"
    limits = limits_type(max_chunks=2)
    store = file_state_module.FileTransferStateStore(tmp_path / "state", limits=limits)

    result = store.accept_chunk(
        order_id="0-0-2026071400000000073",
        file_id="7" * 32,
        business_file_name="bounded.json",
        total_chunks=3,
        chunk_id=1,
        plaintext_chunk=b"small",
    )

    assert result.unpack_status == "rejected"
    assert "chunk count" in result.unpack_message.lower()
    assert list((tmp_path / "state").iterdir()) == []


def test_tar_member_count_member_size_total_size_and_ratio_are_bounded(tmp_path) -> None:
    limits_type = getattr(file_state_module, "FileResourceLimits", None)
    assert limits_type is not None, "tar 解包需要显式资源预算"
    root = f"{'7' * 32}_bounded.json"
    cases = (
        (
            limits_type(max_tar_members=2),
            _archive(root, [("one.json", b"{}"), ("two.json", b"{}")]),
            "member count",
        ),
        (
            limits_type(max_member_bytes=8),
            _archive(root, [("large.json", b"x" * 9)]),
            "member size",
        ),
        (
            limits_type(max_total_decompressed_bytes=8),
            _archive(root, [("one.json", b"12345"), ("two.json", b"6789")]),
            "decompressed",
        ),
        (
            limits_type(max_compression_ratio=1.1),
            _archive(root, [("compressed.json", b"A" * 4096)]),
            "compression ratio",
        ),
    )

    for index, (limits, payload, expected) in enumerate(cases):
        result = _accept(tmp_path / str(index), payload, limits)
        assert result.unpack_status == "failed"
        assert expected in result.unpack_message.lower()


def test_recorder_uses_bounded_multipart_metadata_instead_of_raw_binary(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="bounded-multipart")
    binary = b"--boundary\r\n" + bytes(range(256)) * 32

    recorder.record(
        method="POST",
        path="/ministry/file",
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
        body=binary,
        response={"status": 200},
    )

    record = json.loads(recorder.path.read_text(encoding="utf-8"))
    body = record["body"]
    assert body["kind"] == "multipart/form-data"
    assert body["bytes"] == len(binary)
    assert body["sha256"] == hashlib.sha256(binary).hexdigest()
    assert len(body["preview"]) <= 256
    assert bytes(range(256)).decode("latin-1") not in recorder.path.read_text(encoding="utf-8")


def test_http_rejects_oversized_content_length_without_reading_the_body(tmp_path) -> None:
    server = create_server(
        host="127.0.0.1",
        port=0,
        recorder=FileRecorder(base_dir=tmp_path, run_id="request-limit"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = None
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.putrequest("POST", "/ministry/receive")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        payload = json.loads(response.read())
    finally:
        if connection is not None:
            connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert response.status == 413
    assert "exceeds" in payload["statusText"]


def _multipart_body(boundary: str, parts: list[tuple[str, bytes, str | None]]) -> bytes:
    body = bytearray()
    for name, content, filename in parts:
        body.extend(f"--{boundary}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        body.extend(f"{disposition}\r\n\r\n".encode())
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body)


def test_multipart_part_field_and_file_sizes_are_bounded(monkeypatch) -> None:
    boundary = "resource-boundary"
    content_type = f"multipart/form-data; boundary={boundary}"

    monkeypatch.setattr(envelope_module, "_MAX_MULTIPART_PARTS", 2)
    observation = envelope_module.ProtocolObservation(endpoint_role="platform_file")
    envelope_module._parse_multipart(
        content_type,
        _multipart_body(
            boundary,
            [("one", b"1", None), ("two", b"2", None), ("three", b"3", None)],
        ),
        observation,
    )
    assert any("part count" in error for error in observation.errors)

    monkeypatch.setattr(envelope_module, "_MAX_MULTIPART_FIELD_BYTES", 4)
    observation = envelope_module.ProtocolObservation(endpoint_role="platform_file")
    envelope_module._parse_multipart(
        content_type,
        _multipart_body(boundary, [("orderID", b"12345", None)]),
        observation,
    )
    assert any("field orderID exceeds" in error for error in observation.errors)

    monkeypatch.setattr(envelope_module, "_MAX_FILE_CHUNK_BYTES", 4)
    observation = envelope_module.ProtocolObservation(endpoint_role="platform_file")
    envelope_module._parse_multipart(
        content_type,
        _multipart_body(boundary, [("fileChunk", b"12345", "bounded.tar.gz.bin")]),
        observation,
    )
    assert any("fileChunk exceeds" in error for error in observation.errors)


def test_transfer_cumulative_budget_rejects_and_removes_partial_files(tmp_path) -> None:
    limits = file_state_module.FileResourceLimits(
        max_chunks=4,
        max_chunk_bytes=8,
        max_transfer_bytes=6,
    )
    store = file_state_module.FileTransferStateStore(tmp_path / "state", limits=limits)
    parameters = {
        "order_id": "0-0-2026071400000000077",
        "file_id": "8" * 32,
        "business_file_name": "bounded.json",
        "total_chunks": 2,
    }

    first = store.accept_chunk(**parameters, chunk_id=1, plaintext_chunk=b"1234")
    rejected = store.accept_chunk(**parameters, chunk_id=2, plaintext_chunk=b"5678")

    assert first.unpack_status == "receiving"
    assert rejected.unpack_status == "rejected"
    assert "cumulative" in rejected.unpack_message.lower()
    transfer_dir = store._transfer_dir(parameters["order_id"], parameters["file_id"])
    assert not (transfer_dir / "chunks").exists()
    state = json.loads((transfer_dir / "state.json").read_text(encoding="utf-8"))
    assert state["receivedBytes"] == 0
    assert state["discardedBytes"] == 4
    assert state["receivedChunks"] == []


def test_terminal_metadata_and_duplicate_conflicts_remove_all_payload_bytes(tmp_path) -> None:
    for index, conflict in enumerate(("metadata", "duplicate")):
        store = file_state_module.FileTransferStateStore(tmp_path / conflict)
        common = {
            "order_id": f"0-0-202607140000000008{index}",
            "file_id": str(index + 1) * 32,
            "business_file_name": "bounded.json",
            "total_chunks": 2,
        }
        store.accept_chunk(**common, chunk_id=1, plaintext_chunk=b"first-payload")
        if conflict == "metadata":
            failed = store.accept_chunk(
                **{**common, "business_file_name": "changed.json"},
                chunk_id=2,
                plaintext_chunk=b"second-payload",
            )
        else:
            failed = store.accept_chunk(
                **common,
                chunk_id=1,
                plaintext_chunk=b"conflicting-payload",
            )

        assert failed.unpack_status == "failed"
        transfer_dir = store._transfer_dir(common["order_id"], common["file_id"])
        assert _payload_files(transfer_dir) == []
        state = json.loads((transfer_dir / "state.json").read_text(encoding="utf-8"))
        assert state["receivedBytes"] == 0
        assert state["discardedBytes"] == len(b"first-payload")
        assert state["chunkDigests"]["1"] == hashlib.sha256(b"first-payload").hexdigest()
        assert state["unpackMessage"]


def test_terminal_tar_and_business_validation_failures_remove_all_payload_bytes(tmp_path) -> None:
    cases = (
        ("invalid-tar", b"not-a-tar"),
        (
            "partial-extract",
            _archive(
                f"{'a' * 32}_bounded.json",
                [
                    ("first.txt", b"already-extracted"),
                    (
                        "system-vulnerabilities.json",
                        b'[{"vulInfoID":"missing-required-fields"}]',
                    ),
                ],
            ),
        ),
    )
    for index, (name, payload) in enumerate(cases):
        store = file_state_module.FileTransferStateStore(tmp_path / name)
        order_id = f"0-0-202607140000000009{index}"
        file_id = "a" * 32
        failed = store.accept_chunk(
            order_id=order_id,
            file_id=file_id,
            business_file_name="bounded.json",
            total_chunks=1,
            chunk_id=1,
            plaintext_chunk=payload,
        )

        assert failed.unpack_status == "failed"
        transfer_dir = store._transfer_dir(order_id, file_id)
        assert _payload_files(transfer_dir) == []
        state = json.loads((transfer_dir / "state.json").read_text(encoding="utf-8"))
        assert state["receivedBytes"] == 0
        assert state["discardedBytes"] == len(payload)
        assert state["archiveSha256"] == hashlib.sha256(payload).hexdigest()
        assert state["chunkDigests"]["1"] == hashlib.sha256(payload).hexdigest()
        assert state["unpackMessage"]


def test_completed_transfer_keeps_no_duplicate_chunk_or_archive_copy(tmp_path) -> None:
    root = f"{'9' * 32}_bounded.json"
    archive = _archive(root, [("bounded.json", b'{"visible":true}')])
    store = file_state_module.FileTransferStateStore(tmp_path / "state")

    result = store.accept_chunk(
        order_id="0-0-2026071400000000078",
        file_id="9" * 32,
        business_file_name="bounded.json",
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=archive,
    )

    assert result.unpack_status == "completed"
    replay = store.accept_chunk(
        order_id="0-0-2026071400000000078",
        file_id="9" * 32,
        business_file_name="bounded.json",
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=archive,
    )
    assert replay == result
    transfer_dir = store._transfer_dir(
        "0-0-2026071400000000078",
        "9" * 32,
    )
    assert not (transfer_dir / "chunks").exists()
    assert not (transfer_dir / "assembled.tar.gz").exists()
    assert (transfer_dir / "unpacked" / "bounded.json").is_file()


def test_request_concurrency_limiter_rejects_saturation_without_leaking_slots() -> None:
    from mock_ministry.mocks.protocol_ministry_platform import server as server_module

    limiter_type = getattr(server_module, "RequestConcurrencyLimiter", None)
    assert limiter_type is not None, "HTTP 请求需要有界并发控制"
    limiter = limiter_type(1)
    entered = threading.Event()
    release = threading.Event()

    def hold_slot() -> None:
        assert limiter.acquire() is True
        entered.set()
        assert release.wait(timeout=2)
        limiter.release()

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(hold_slot)
        assert entered.wait(timeout=2)
        assert limiter.acquire() is False
        release.set()
        future.result(timeout=2)

    assert limiter.acquire() is True
    limiter.release()


def test_http_request_concurrency_rejects_a_simultaneous_request(tmp_path) -> None:
    server = create_server(
        host="127.0.0.1",
        port=0,
        recorder=FileRecorder(base_dir=tmp_path, run_id="concurrency-limit"),
        max_concurrent_requests=1,
    )
    server.upload_barrier.configure("arm", timeout_seconds=5)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    first_status: list[int] = []

    def blocked_upload() -> None:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        try:
            connection.request("POST", "/ministry/file", body=b"")
            response = connection.getresponse()
            first_status.append(response.status)
            response.read()
        finally:
            connection.close()

    upload_thread = threading.Thread(target=blocked_upload, daemon=True)
    upload_thread.start()
    try:
        deadline = time.monotonic() + 2
        while server.upload_barrier.status()["entered"] != 1:
            assert time.monotonic() < deadline, "上传请求未进入并发占用状态"
            time.sleep(0.01)
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            payload = json.loads(response.read())
        finally:
            connection.close()
        assert response.status == 503
        assert "concurrency" in payload["statusText"]
    finally:
        server.upload_barrier.configure("release")
        upload_thread.join(timeout=5)
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert first_status
