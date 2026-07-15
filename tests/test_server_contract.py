from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.request import Request, urlopen

from mock_ministry.recorder import FileRecorder
from mock_ministry.server import ACCEPTED_RESPONSE, create_server
from mock_ministry.mocks.protocol_ministry_platform.additional_fixtures import build_additional_fixture


def test_server_accepts_receive_post(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="server")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        body = json.dumps(
            {
                "orderID": "2-301-2026070300000000001",
                "orgCode": "MIIT",
                "ispCode": "CMCC",
                "ctxCode": 0,
                "reqMsgCnt": json.dumps({"orderType": 2, "orderSubType": 301}),
            }
        ).encode("utf-8")
        request = Request(
            f"http://{host}:{port}/ministry/receive",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200

        assert payload == ACCEPTED_RESPONSE
        record = json.loads(recorder.path.read_text(encoding="utf-8").strip())
        assert record["path"] == "/ministry/receive"
        assert record["response"]["body"] == ACCEPTED_RESPONSE
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_server_refreshes_ministry_access_token_on_receive_path(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="auth")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        request = Request(
            f"http://{host}:{port}/ministry/receive",
            data=json.dumps(
                {
                    "orgCode": "792713",
                    "ispCode": "CM",
                    "publicKey": "encrypted-device-hash",
                    "ip": "127.0.0.1",
                    "domain": "http://127.0.0.1:8000",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200

        assert payload == {
            "accessToken": "mock-ministry-access-token",
            "expiresIn": 3600,
        }
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

def test_server_control_injects_one_real_response_then_resets(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="controlled")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        control = Request(
            f"http://{host}:{port}/__control/scenario",
            data=json.dumps(
                {
                    "scenario": "interface11_failure",
                    "remaining": 1,
                    "path": "/ministry/receive",
                    "orderID": "2-104-2026071400000000049",
                    "routeType": 2,
                    "routeSubType": 104,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(control, timeout=5) as response:
            assert json.loads(response.read())["scenario"] == "interface11_failure"

        fixture = build_additional_fixture(11, "2026071400000000049")
        body = {
            key: value
            for key, value in fixture.items()
            if key in {"orderID", "orgCode", "ispCode", "ctxCode"}
        }
        body["reqMsgCnt"] = json.dumps(fixture["inner"])
        request = Request(
            f"http://{host}:{port}/ministry/receive",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            first = json.loads(response.read())
        with urlopen(request, timeout=5) as response:
            second = json.loads(response.read())
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert first["statusCode"] == 1
    assert second["statusCode"] == 0


def test_server_control_resets_only_the_selected_file_order(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="file-reset")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        control = Request(
            f"http://{host}:{port}/__control/file-transfer",
            data=json.dumps(
                {"action": "reset", "orderID": "0-0-2026071400000000099"}
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(control, timeout=5) as response:
            payload = json.loads(response.read())
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert payload == {
        "action": "reset",
        "orderID": "0-0-2026071400000000099",
        "removed": 0,
    }


def test_failure_injection_is_scoped_and_consumed_after_target_identification() -> None:
    from mock_ministry.mocks.protocol_ministry_platform.server import ScenarioController

    controller = ScenarioController("success")
    configured = controller.configure(
        "interface11_failure",
        remaining=1,
        path="/ministry/receive",
        order_id="2-104-2026071400000000071",
        route_type=2,
        route_subtype=104,
        request_key="request-71",
    )
    unrelated = SimpleNamespace(
        path="/ministry/receive",
        order_id="2-104-2026071400000000070",
        order_type=2,
        sub_type=104,
    )
    target = SimpleNamespace(
        path="/ministry/receive",
        order_id="2-104-2026071400000000071",
        order_type=2,
        sub_type=104,
    )

    assert configured["remaining"] == 1
    assert controller.consume(unrelated, request_key="request-71") == "success"
    assert controller.status()["remaining"] == 1
    assert controller.consume(target, request_key="wrong-key") == "success"
    assert controller.status()["remaining"] == 1
    assert controller.consume(target, request_key="request-71") == "interface11_failure"
    assert controller.consume(target, request_key="request-71") == "success"


def test_failure_injection_is_concurrency_safe_and_only_one_target_consumes_it() -> None:
    from mock_ministry.mocks.protocol_ministry_platform.server import ScenarioController

    controller = ScenarioController("success")
    controller.configure(
        "file_failed",
        remaining=1,
        path="/ministry/file",
        order_id="0-0-2026071400000000072",
        route_type=0,
        route_subtype=0,
    )
    target = SimpleNamespace(
        path="/ministry/file",
        order_id="0-0-2026071400000000072",
        order_type=0,
        sub_type=0,
    )
    gate = threading.Barrier(3)

    def consume() -> str:
        gate.wait(timeout=2)
        return controller.consume(target)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(consume) for _ in range(2)]
        gate.wait(timeout=2)
        observed = sorted(future.result(timeout=2) for future in futures)

    assert observed == ["file_failed", "success"]


def test_failure_injection_keeps_unrelated_arms_and_consumes_each_target_atomically() -> None:
    from mock_ministry.mocks.protocol_ministry_platform.server import ScenarioController

    controller = ScenarioController("success")
    first = SimpleNamespace(
        path="/ministry/receive",
        order_id="2-104-2026071400000000073",
        order_type=2,
        sub_type=104,
    )
    second = SimpleNamespace(
        path="/ministry/file",
        order_id="0-0-2026071400000000074",
        order_type=0,
        sub_type=0,
    )
    controller.configure(
        "interface11_failure",
        remaining=1,
        path=first.path,
        order_id=first.order_id,
        route_type=first.order_type,
        route_subtype=first.sub_type,
        request_key="receive-73",
    )
    configured = controller.configure(
        "file_failed",
        remaining=1,
        path=second.path,
        order_id=second.order_id,
        route_type=second.order_type,
        route_subtype=second.sub_type,
        request_key="file-74",
    )

    assert configured["armedCount"] == 2
    assert controller.consume(first, request_key="receive-73") == "interface11_failure"
    assert controller.status()["armedCount"] == 1
    assert controller.consume(second, request_key="file-74") == "file_failed"
    assert controller.status() == {
        "scenario": "success",
        "remaining": 0,
        "target": None,
        "armed": [],
        "armedCount": 0,
    }


def test_simultaneous_failure_targets_do_not_consume_or_remove_each_other() -> None:
    from mock_ministry.mocks.protocol_ministry_platform.server import ScenarioController

    controller = ScenarioController("success")
    observations = (
        SimpleNamespace(
            path="/ministry/receive",
            order_id="2-104-2026071400000000075",
            order_type=2,
            sub_type=104,
        ),
        SimpleNamespace(
            path="/ministry/file",
            order_id="0-0-2026071400000000076",
            order_type=0,
            sub_type=0,
        ),
    )
    scenarios = ("interface11_failure", "file_failed")
    keys = ("receive-75", "file-76")
    for observation, scenario, request_key in zip(observations, scenarios, keys, strict=True):
        controller.configure(
            scenario,
            remaining=1,
            path=observation.path,
            order_id=observation.order_id,
            route_type=observation.order_type,
            route_subtype=observation.sub_type,
            request_key=request_key,
        )

    gate = threading.Barrier(3)

    def consume(index: int) -> str:
        gate.wait(timeout=2)
        return controller.consume(observations[index], request_key=keys[index])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(consume, index) for index in range(2)]
        gate.wait(timeout=2)
        observed = {future.result(timeout=2) for future in futures}

    assert observed == set(scenarios)
    assert controller.status()["armedCount"] == 0
