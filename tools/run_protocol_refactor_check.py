from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_ministry.mocks.protocol_ministry_platform.runner import run_refactor_check


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mock-driven protocol refactor verification.")
    parser.add_argument("--backend-base-url", required=True)
    parser.add_argument("--record-dir", default="reports/mock-server")
    parser.add_argument("--mode", choices=["observe", "contract"], default="observe")
    parser.add_argument("--mock-host", default="127.0.0.1")
    parser.add_argument("--mock-port", type=int, default=18080)
    parser.add_argument("--send-case", action="append", default=[])
    parser.add_argument("--outbound-path", action="append", default=[])
    parser.add_argument("--output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_refactor_check(
        backend_base_url=args.backend_base_url,
        record_dir=args.record_dir,
        mode=args.mode,
        send_cases=args.send_case or ["policy_302"],
        outbound_paths=args.outbound_path,
        mock_host=args.mock_host,
        mock_port=args.mock_port,
    )
    content = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)
    return 0 if result["report"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
