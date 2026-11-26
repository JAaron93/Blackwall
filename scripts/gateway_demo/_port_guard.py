"""Exit 0 when a TCP port is already served, 1 when it is free (TASK-G06).

Used by ``run_gateway_demo.sh`` to refuse a honeypot showcase when port 8765
is occupied by a stale server. Keeping the check in a named helper makes the
inverted-condition regression testable without launching a full demo.
"""

from __future__ import annotations

import socket
import sys


def is_port_occupied(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or not args[0].isdigit():
        print("usage: _port_guard.py <port>", file=sys.stderr)
        return 2
    return 0 if is_port_occupied(int(args[0])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
