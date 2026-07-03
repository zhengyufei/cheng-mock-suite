from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_ministry.recorder import FileRecorder
from mock_ministry.server import create_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local ministry mock receiver.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--record-dir", default="reports/mock-server")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    recorder = FileRecorder(base_dir=args.record_dir)
    server = create_server(host=args.host, port=args.port, recorder=recorder)
    host, port = server.server_address
    print(f"ministry mock receiver listening on http://{host}:{port}")
    print(f"recording requests to {recorder.path}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopping ministry mock receiver")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
