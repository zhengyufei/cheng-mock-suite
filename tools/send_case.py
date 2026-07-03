from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_ministry.cases import build_plain_envelope, load_case


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send one ministry fixture to a backend receive endpoint.")
    parser.add_argument("--case", required=True, help="Fixture case name, for example policy_302")
    parser.add_argument("--base-url", required=True, help="Backend base URL, for example http://127.0.0.1:8000")
    parser.add_argument("--path", default="/api/ministry/receive")
    parser.add_argument(
        "--plain",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Send a plain envelope. Encrypted envelopes are not implemented in this skeleton.",
    )
    return parser.parse_args()


def build_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def main() -> int:
    args = parse_args()
    if not args.plain:
        print("encrypted envelope generation is not implemented in this mock skeleton", file=sys.stderr)
        return 2

    case = load_case(args.case)
    envelope = build_plain_envelope(case)
    target = build_url(args.base_url, args.path)

    try:
        response = requests.post(
            target,
            data=json.dumps(envelope, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 2

    print(f"POST {target}")
    print(f"status: {response.status_code}")
    print(response.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
