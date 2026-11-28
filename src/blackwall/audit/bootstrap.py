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
import site
import sys
import sysconfig
import time
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
_GUARD_REGISTERED = False
_PROTECTED_FILENAMES = frozenset({"sitecustomize.py", MANIFEST_NAME, ".zshrc", ".bash_profile"})


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


def _trusted_entrypoints() -> set[str]:
    """Locations of installer/CLI entry points in the active Python environment.

    Using ``PATH`` lookup here would let a launcher plant its own ``pip`` ahead
    of the real one; using the environment's scripts directory avoids that.
    """
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    names = ("pip", "pip3", f"pip{version}", "blackwall")
    directories: list[Path] = []
    try:
        directories.append(Path(sysconfig.get_paths()["scripts"]))
    except (KeyError, TypeError, OSError):
        pass
    directories.extend([Path(sys.prefix) / "bin", Path(sys.prefix) / "Scripts"])
    return {
        os.path.realpath(str(directory / name))
        for directory in directories
        for name in names
    }


def _matches_trusted_entrypoint(candidate: str) -> bool:
    """Match only genuine installer/CLI entry points in this environment."""
    return os.path.realpath(candidate) in _trusted_entrypoints()


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


def _register_critical_guard() -> None:
    """Block writes to the bootstrap and persistence files we rely on.

    ``AuditHookManager`` protects OS-critical paths but not user-home files;
    without this guard a hooked rogue process could strip its own bootstrap or
    plant a LaunchAgent that runs outside Python at next login.
    """
    global _GUARD_REGISTERED
    if not _GUARD_REGISTERED:
        sys.addaudithook(_critical_bootstrap_guard)
        _GUARD_REGISTERED = True


def _critical_bootstrap_guard(event: str, args: tuple[Any, ...]) -> None:
    if event != "open" or not args:
        return
    raw = args[0]
    if isinstance(raw, int):
        return
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="ignore")
    elif isinstance(raw, str):
        text = raw
    else:
        return

    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 else None
    is_write = False
    if isinstance(mode, (str, bytes)):
        mode_text = mode if isinstance(mode, str) else mode.decode("utf-8", errors="ignore")
        is_write = any(char in mode_text for char in ("w", "a", "x", "+"))
    elif isinstance(flags, int):
        is_write = (flags & 3) in (os.O_WRONLY, os.O_RDWR)
    if not is_write:
        return

    real = os.path.realpath(text)
    name = os.path.basename(real)
    if (
        name in _PROTECTED_FILENAMES
        or (name.endswith(".plist") and "/Library/LaunchAgents/" in real)
        or (name == "policy.yaml" and "/.blackwall/" in real)
    ):
        raise PermissionError(
            "PermissionError: Protected bootstrap/persistence file write denied"
        )


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
    # DISABLE_ENV is deliberately ignored here: a rogue parent controls the
    # environment of the Python children it launches, so an inherited opt-out
    # cannot be distinguished from an operator's. Only genuine installer/CLI
    # entry points are exempt via _is_exempt_process().
    if _is_exempt_process():
        return
    _register_critical_guard()

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
        # Quarantine a corrupt/unusable DB rather than bricking every Python
        # process on the account; only fail closed when recovery is impossible.
        try:
            quarantine = db_path.with_name(f"{db_path.name}.corrupt-{time.time_ns()}")
            db_path.replace(quarantine)
            manager = manager_module.AuditHookManager(db_path=str(db_path))
            manager._get_conn()
            manager.start()
        except Exception as recovery_exc:
            _fail_closed(f"{exc}; DB recovery failed: {recovery_exc}")
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
