#!/usr/bin/env python3
from __future__ import annotations

import sys


def main() -> int:
    print(
        "gateway runtime is not activated; install AstrBot and an approved runner first",
        file=sys.stderr,
    )
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
