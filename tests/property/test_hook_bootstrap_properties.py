"""Property checks for non-destructive sitecustomize injection (TASK-F02)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.audit import bootstrap


@settings(max_examples=30, deadline=None)
@given(
    original=st.text(
        alphabet="abcXYZ0123 #\n\r_=", min_size=1, max_size=120
    ).filter(lambda value: bool(value.strip()))
)
def test_uninstall_is_byte_for_byte_identity(original: str) -> None:
    raw = original.encode("utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        site_dir = Path(tmp)
        sitecustomize = site_dir / "sitecustomize.py"
        sitecustomize.write_bytes(raw)
        bootstrap.install_hook([site_dir])
        bootstrap.uninstall_hook([site_dir])
        assert sitecustomize.read_bytes() == raw
