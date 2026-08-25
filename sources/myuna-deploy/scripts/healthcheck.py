#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from urllib.request import urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a loopback Myuna health endpoint")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}/healthz"
    with urlopen(url, timeout=args.timeout) as response:
        payload = json.load(response)
        if response.status != 200 or payload.get("status") != "alive":
            raise SystemExit(f"unhealthy response: status={response.status} payload={payload}")
    print(json.dumps({"url": url, "result": "healthy", "payload": payload}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
