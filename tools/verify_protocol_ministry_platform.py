from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_ministry.mocks.protocol_ministry_platform.assertions import evaluate_records
from mock_ministry.mocks.protocol_ministry_platform.evidence import latest_run_dir, load_records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify protocol ministry platform mock evidence.")
    parser.add_argument("--record-file")
    parser.add_argument("--record-dir", default="reports/mock-server")
    parser.add_argument("--mode", choices=["observe", "contract"], default="observe")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--output")
    return parser.parse_args()


def _resolve_record_file(args: argparse.Namespace) -> Path:
    if args.record_file:
        return Path(args.record_file)
    return latest_run_dir(args.record_dir) / "requests.jsonl"


def _to_markdown(payload: dict) -> str:
    lines = [
        f"# protocol-ministry-platform {payload['mode']} report",
        "",
        f"- ok: `{payload['ok']}`",
        f"- total: `{payload['summary']['total']}`",
        f"- failures: `{len(payload['failures'])}`",
        f"- warnings: `{len(payload['warnings'])}`",
        "",
        "## Failures",
    ]
    lines.extend(f"- {item}" for item in payload["failures"] or ["无"])
    lines.extend(["", "## Warnings"])
    lines.extend(f"- {item}" for item in payload["warnings"] or ["无"])
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    records = load_records(_resolve_record_file(args))
    report = evaluate_records(records, mode=args.mode)
    payload = report.to_dict()

    if args.format == "json":
        content = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        content = _to_markdown(payload)

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
    else:
        print(content)

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
