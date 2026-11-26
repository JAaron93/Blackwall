"""Exec a demo subprocess in its own session (TASK-G06 cleanup support).

The orchestration scripts launch scenarios and the honeypot in a new session
so a single ``kill -TERM -- -<pid>`` reaches their entire process tree on
SIGTERM/SIGINT. ``os.setsid()`` raises when the caller is already a process
group leader (e.g. ``bash -m`` job control); in that case the child is already
isolated in its own process group and exec proceeds unchanged.
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: _isolated_exec.py <command> [args...]", file=sys.stderr)
        return 2
    try:
        os.setsid()
    except OSError:
        pass
    os.execvp(args[0], args)  # pragma: no cover - never returns on success
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
