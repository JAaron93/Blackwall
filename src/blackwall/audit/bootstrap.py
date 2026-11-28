"""Global Python audit hook auto-bootstrap for Blackwall Core (FR-12 / TASK-F02).

``blackwall hook install`` injects a small marked snippet into the
``sitecustomize.py`` of the active virtualenv and the user site-packages so a
fresh Python process attaches Blackwall's ``sys.addaudithook`` before user code
runs.  ``uninstall`` removes only that marked block, preserving all pre-existing
customizations byte-for-byte.

The snippet deliberately skips ``pip``/PEP-517 build invocations: ``pip`` is a
Python program that spawns ``subprocess.Popen`` before ``setup.py`` runs, and
the audit hook blocks every subprocess by design.  An explicit opt-out env var
is also supported for installers and offline tooling.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import site
import sys
import sysconfig
from pathlib import Path
from typing import Any

BOOTSTRAP_START = "# BEGIN BLACKWALL AUDIT HOOK BOOTSTRAP"
BOOTSTRAP_END = "# END BLACKWALL AUDIT HOOK BOOTSTRAP"
MANIFEST_NAME = "blackwall_hook_bootstrap_manifest.json"
DISABLE_ENV = "BLACKWALL_AUDIT_DISABLED"
DB_ENV = "BLACKWALL_AUDIT_DB"

_START_BYTES = BOOTSTRAP_START.encode("utf-8")
_END_BYTES = BOOTSTRAP_END.encode("utf-8")

_BOOTSTRAPPED = False


def default_db_path() -> Path:
    """Resolve the default audit DB at call time (HOME may vary per process)."""
    return Path.home() / ".blackwall" / "audit.db"


def generate_snippet() -> str:
    """Return the marked sitecustomize snippet.

    Only ``ImportError`` is swallowed: it means this interpreter does not have
    the Blackwall package installed and the bootstrap cannot run there.  Real
    initialization failures terminate the interpreter via ``os._exit`` because
    CPython otherwise swallows ``sitecustomize`` exceptions and would start
    user code with no hook attached (fail open).
    """
    return "\n".join(
        [
            BOOTSTRAP_START,
            "try:",
            "    from blackwall.audit.bootstrap import bootstrap_audit_hook",
            "    bootstrap_audit_hook()",
            "except ImportError:",
            "    pass",
            BOOTSTRAP_END,
            "",
        ]
    )


def discover_site_packages() -> list[Path]:
    """Locate the active venv site-packages and the user site-packages."""
    candidates: list[Path] = []
    try:
        candidates.append(Path(site.getusersitepackages()))
    except (AttributeError, RuntimeError):
        pass
    if getattr(sys, "prefix", None) != getattr(sys, "base_prefix", None):
        purelib = sysconfig.get_paths().get("purelib")
        if purelib:
            candidates.append(Path(purelib))
    seen: set[Path] = set()
    result: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        # Keep a missing user-site path: install creates it. Dropping it made
        # `hook install` silently do nothing outside a virtualenv.
        if resolved not in seen:
            seen.add(resolved)
            result.append(resolved)
    return result


def _block_region(data: bytes) -> tuple[int, int] | None:
    start = data.find(_START_BYTES)
    if start == -1:
        return None
    end = data.find(_END_BYTES, start)
    if end == -1:
        return None
    prefix = data[:start]
    line_start = max(prefix.rfind(b"\n"), prefix.rfind(b"\r")) + 1
    tail_start = end + len(_END_BYTES)
    tail = data[tail_start:]
    separators = [index for sep in (b"\n", b"\r") if (index := tail.find(sep)) != -1]
    line_end = tail_start + min(separators) + 1 if separators else len(data)
    return line_start, line_end


def _read_manifest(site_dir: Path) -> dict[str, Any]:
    path = site_dir / MANIFEST_NAME
    if not path.is_file():
        return {"created": False, "inserted_separator": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"created": False, "inserted_separator": False}
    return {
        "created": bool(payload.get("created", False)),
        "inserted_separator": bool(payload.get("inserted_separator", False)),
    }


def _write_manifest(site_dir: Path, created: bool, inserted_separator: bool) -> None:
    path = site_dir / MANIFEST_NAME
    path.write_text(
        json.dumps({"created": created, "inserted_separator": inserted_separator}),
        encoding="utf-8",
    )
    path.chmod(0o600)


def install_hook(site_packages: list[Path] | None = None) -> list[Path]:
    """Inject the marked bootstrap into each target sitecustomize.py."""
    targets = site_packages if site_packages is not None else discover_site_packages()
    snippet = generate_snippet().encode("utf-8")
    for site_dir in targets:
        path = site_dir / "sitecustomize.py"
        site_dir.mkdir(parents=True, exist_ok=True)
        existing = path.read_bytes() if path.is_file() else b""
        region = _block_region(existing)
        if region is not None:
            # Replace the existing marked block in place; keep its manifest flags.
            path.write_bytes(existing[: region[0]] + snippet + existing[region[1] :])
            continue
        created = not path.exists()
        inserted_separator = bool(existing) and not existing.endswith((b"\n", b"\r"))
        separator = b"\n" if inserted_separator else b""
        path.write_bytes(existing + separator + snippet)
        _write_manifest(site_dir, created, inserted_separator)
    return targets


def uninstall_hook(site_packages: list[Path] | None = None) -> list[Path]:
    """Remove only the marked bootstrap, restoring the original file bytes."""
    targets = site_packages if site_packages is not None else discover_site_packages()
    for site_dir in targets:
        path = site_dir / "sitecustomize.py"
        flags = _read_manifest(site_dir)
        manifest_exists = (site_dir / MANIFEST_NAME).is_file()
        (site_dir / MANIFEST_NAME).unlink(missing_ok=True)
        if not path.is_file():
            continue
        data = path.read_bytes()
        region = _block_region(data)
        if region is None:
            continue
        start, end = region
        if flags["inserted_separator"] and start > 0 and data[start - 1 : start] == b"\n":
            start -= 1
        remaining = data[:start] + data[end:]
        if not remaining.strip() and (flags["created"] or not manifest_exists):
            path.unlink()
        else:
            # Preserve customizations added after installation, even when the
            # bootstrap originally created this file.
            path.write_bytes(remaining)
    return targets


def _matches_trusted_entrypoint(candidate: str) -> bool:
    """Match only real, PATH-resolved pip/Blackwall entry points.

    Trusting a filename prefix or an argument name lets a rogue script opt out
    simply by naming itself ``pipfetch.py`` or passing ``build`` as an argument.
    """
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    for name in ("pip", "pip3", f"pip{version}", "blackwall"):
        located = shutil.which(name)
        if located and os.path.realpath(candidate) == os.path.realpath(located):
            return True
    return False


def _is_python_executable(name: str) -> bool:
    base = Path(name).name.lower()
    return base == "python" or base == "python3" or (
        base.startswith("python3.") and base[8:].isdigit()
    )


def _is_exempt_process() -> bool:
    """Skip genuine installers and trusted Blackwall CLI processes only."""
    argv = [str(part) for part in (sys.argv or [])]
    if not argv:
        return False
    if _matches_trusted_entrypoint(argv[0]):
        return True
    if not _is_python_executable(argv[0]):
        return False
    if len(argv) > 2 and argv[1] == "-m":
        return argv[2] in ("pip", "build", "blackwall.cli")
    return len(argv) > 1 and _matches_trusted_entrypoint(argv[1])


def _fail_closed(message: str) -> None:
    """Refuse to start an unprotected interpreter when hook setup fails.

    CPython swallows exceptions raised by ``sitecustomize`` and continues into
    user code, so merely raising here would leave rogue scripts unblocked.
    """
    sys.stderr.write(f"Blackwall audit hook failed to initialize: {message}\n")
    sys.stderr.flush()
    os._exit(1)


def _stop_manager(manager: Any) -> None:
    try:
        manager.stop()
    except Exception:
        # atexit must never raise during interpreter shutdown.
        pass


def bootstrap_audit_hook() -> None:
    """Attach the global AuditHookManager in a freshly started interpreter."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    if os.environ.get(DISABLE_ENV, "").strip().lower() in ("1", "true", "yes"):
        return
    if _is_exempt_process():
        return

    from blackwall.audit import manager as manager_module

    if getattr(manager_module, "_hook_registered", False) and any(
        getattr(candidate, "enabled", False)
        for candidate in getattr(manager_module, "_active_managers", [])
    ):
        _BOOTSTRAPPED = True
        return

    db_value = os.environ.get(DB_ENV)
    db_path = Path(db_value).expanduser().resolve() if db_value else default_db_path()
    try:
        manager = manager_module.AuditHookManager(db_path=str(db_path))
        # Create the SQLite schema before the hook starts intercepting `open`.
        manager._get_conn()
        manager.start()
    except Exception as exc:
        _fail_closed(str(exc))
        return  # unreachable when os._exit succeeds
    _BOOTSTRAPPED = True
    atexit.register(_stop_manager, manager)


def hook_status() -> dict[str, Any]:
    """Report installed snippet paths and whether the hook is active now."""
    targets = discover_site_packages()
    installed = [
        str(site_dir / "sitecustomize.py")
        for site_dir in targets
        if (site_dir / "sitecustomize.py").is_file()
        and _block_region((site_dir / "sitecustomize.py").read_bytes()) is not None
    ]
    from blackwall.audit import manager as manager_module

    active = bool(getattr(manager_module, "_hook_registered", False)) and any(
        getattr(candidate, "enabled", False)
        for candidate in getattr(manager_module, "_active_managers", [])
    )
    return {"installed": bool(installed), "paths": installed, "active": active}
