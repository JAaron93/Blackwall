"""Cross-Platform Service Manager for Blackwall MCP Gateway (TASK-F01).

Manages native background services:
- macOS ``launchd`` (``~/Library/LaunchAgents/com.blackwall.gateway.plist``)
- Linux ``systemd`` (``~/.config/systemd/user/blackwall.service`` or
  ``/etc/systemd/system/blackwall.service`` with ``--system``)

Invariants (FR-10, R54/R55):
- Absolute path resolution via ``Path.resolve()``; zero raw ``~`` in outputs.
- Supervised execution is always ``blackwall serve --foreground`` with
  ``Type=exec`` + ``PIDFile=`` under systemd.
- systemd rate limits (``StartLimitBurst``/``StartLimitIntervalSec``) live
  strictly under ``[Unit]``.
- System units use FHS paths + non-root ``User=``/``Group=`` (never root).
- Install fails fast when GCP project or ADC credentials are absent.
"""

from __future__ import annotations

import logging
import os
import pwd
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

LAUNCHD_LABEL = "com.blackwall.gateway"
LAUNCHD_PLIST_NAME = f"{LAUNCHD_LABEL}.plist"
SYSTEMD_SERVICE_NAME = "blackwall.service"

FHS_CONFIG = Path("/etc/blackwall/gateway.yaml")
FHS_PID = Path("/run/blackwall/blackwall.pid")
FHS_LOG = Path("/var/log/blackwall/blackwall.log")
FHS_DB = Path("/var/lib/blackwall/threat_signatures.db")
SYSTEM_CREDENTIALS_PATH = Path("/etc/blackwall/credentials.json")
SYSTEM_ENV_FILE = Path("/etc/default/blackwall")

DEDICATED_USER = "blackwall"
DEDICATED_HOME = Path("/var/lib/blackwall")


def detect_platform(system: str | None = None) -> str:
    """Return ``darwin`` or ``linux`` for the host OS.

    Raises ``RuntimeError`` on Windows or other unsupported platforms.
    """
    name = (system if system is not None else __import__("platform").system()).lower()
    if name == "darwin":
        return "darwin"
    if name == "linux":
        return "linux"
    raise RuntimeError(f"Unsupported platform for Blackwall service manager: {name!r}")


def resolve_absolute(path_str: str | Path) -> Path:
    """Expand user and resolve to an absolute filesystem path.

    Usesabspath (no symlink chase) so Linux FHS constants (``/run``,
    ``/var``) remain stable when tests run on macOS where ``/var`` is a
    symlink to ``/private/var``. Output is always absolute with zero ``~``.
    """
    expanded = os.path.expanduser(str(path_str))
    return Path(os.path.abspath(expanded))


def assert_no_tilde(content: str) -> None:
    """Raise ``ValueError`` if raw ``~`` appears in generated service content."""
    if "~" in content:
        raise ValueError("Generated service definition contains unexpanded '~'")


def get_gcp_project(project_override: str | None = None) -> str:
    """Return configured GCP project or raise ``ValueError`` (fail-fast)."""
    project = (
        (project_override or "").strip()
        or os.environ.get("GCP_PROJECT", "").strip()
        or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    )
    if not project:
        raise ValueError(
            "Missing GCP Project: set GCP_PROJECT / GOOGLE_CLOUD_PROJECT "
            "or pass --project <id>."
        )
    return project


def get_service_home(explicit_home: Path | None = None, system_user: str | None = None) -> Path:
    """Resolve the service user's home directory for ADC fallback."""
    if explicit_home is not None:
        return Path(explicit_home).expanduser().resolve()
    if system_user and system_user not in ("blackwall", ""):
        try:
            return Path(pwd.getpwnam(system_user).pw_dir).resolve()
        except KeyError:
            pass
    if system_user == DEDICATED_USER:
        return DEDICATED_HOME
    return Path.home()


def resolve_adc_path(
    explicit: str | None = None, service_home: Path | None = None
) -> Path | None:
    """Resolve ADC credentials path, preferring explicit config.

    Order: explicit arg > ``GOOGLE_APPLICATION_CREDENTIALS`` > standard user ADC
    under ``<service_home>/.config/gcloud/application_default_credentials.json``.
    Returns ``None`` when no candidate exists on disk.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(resolve_absolute(explicit))
    env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if env_path:
        candidates.append(resolve_absolute(env_path))
    home = get_service_home(service_home)
    candidates.append(home / ".config" / "gcloud" / "application_default_credentials.json")
    for cand in candidates:
        try:
            if cand.is_file():
                return cand.resolve()
        except OSError:
            continue
    return None


def derive_system_user(explicit_user: str | None = None) -> tuple[str, str]:
    """Derive non-root systemd execution identity.

    Priority: explicit ``--user`` > ``SUDO_USER`` > dedicated ``blackwall``.
    Raises ``ValueError`` for ``root``.
    """
    candidate = (explicit_user or "").strip() or os.environ.get("SUDO_USER", "").strip() or DEDICATED_USER
    if candidate == "root":
        raise ValueError("Running systemd units as root (User=root) is strictly disallowed.")
    return candidate, candidate


def get_blackwall_executable() -> str:
    """Return absolute path to the blackwall executable for ExecStart.

    Callers MUST NOT append ``serve`` directly to ``sys.executable``: when
    ``blackwall`` is absent from ``PATH`` the runnable entrypoint is
    ``python -m blackwall.cli``. Use :func:`build_service_command` instead.
    """
    found = shutil.which("blackwall")
    if found:
        return str(resolve_absolute(found))
    return str(resolve_absolute(sys.executable))


def build_service_command_prefix() -> list[str]:
    """Return executable prefix that can run ``serve --foreground``.

    Either ``[blackwall]`` or ``[python, -m, blackwall.cli]`` fallback so the
    generated ``ExecStart``/``ProgramArguments`` always start a real gateway.
    """
    found = shutil.which("blackwall")
    if found:
        return [str(resolve_absolute(found))]
    return [str(resolve_absolute(sys.executable)), "-m", "blackwall.cli"]


def build_exec_args(
    config_path: str,
    pidfile_path: str,
    logfile_path: str,
    db_path: str,
    wrap_cmd: str | None = None,
    port: int = 9229,
) -> list[str]:
    """Build ``serve --foreground`` argument list (excluding executable)."""
    args = [
        "serve",
        "--foreground",
        "--transport",
        "http",
        "--port",
        str(port),
    ]
    if wrap_cmd:
        args += ["--wrap", wrap_cmd]
    else:
        args += ["--config", config_path]
    args += ["--pidfile", pidfile_path, "--logfile", logfile_path, "--db", db_path]
    return args


def _escape_xml(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def generate_launchd_plist(
    config_path: str,
    pidfile_path: str,
    logfile_path: str,
    db_path: str,
    wrap_cmd: str | None,
    env: dict[str, str],
    label: str = LAUNCHD_LABEL,
    port: int = 9229,
) -> str:
    """Generate macOS launchd plist XML supervising ``serve --foreground``."""
    cfg = str(resolve_absolute(config_path))
    pid = str(resolve_absolute(pidfile_path))
    log = str(resolve_absolute(logfile_path))
    db = str(resolve_absolute(db_path))
    prefix = build_service_command_prefix()
    for value in (cfg, pid, log, db, *prefix):
        assert_no_tilde(value)
    args = build_exec_args(cfg, pid, log, db, wrap_cmd, port)
    program_args = prefix + args
    program_xml = "\n".join(f"        <string>{_escape_xml(a)}</string>" for a in program_args)
    env_entries = []
    for key in ("GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_APPLICATION_CREDENTIALS", "GEMINI_TIER", "PATH"):
        if key in env and env[key]:
            env_entries.append(
                f"        <key>{_escape_xml(key)}</key>\n        <string>{_escape_xml(env[key])}</string>"
            )
    env_xml = "\n".join(env_entries)
    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_escape_xml(label)}</string>
    <key>ProgramArguments</key>
    <array>
{program_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>EnvironmentVariables</key>
    <dict>
{env_xml}
    </dict>
    <key>StandardOutPath</key>
    <string>{_escape_xml(log)}</string>
    <key>StandardErrorPath</key>
    <string>{_escape_xml(log)}</string>
</dict>
</plist>
"""
    assert_no_tilde(content)
    return content


def generate_systemd_unit(
    config_path: str,
    pidfile_path: str,
    logfile_path: str,
    db_path: str,
    wrap_cmd: str | None,
    env: dict[str, str],
    system: bool = False,
    user: str | None = None,
    group: str | None = None,
    port: int = 9229,
) -> str:
    """Generate systemd unit with correct ``[Unit]``/``[Service]`` sectioning."""
    cfg = str(resolve_absolute(config_path))
    pid = str(resolve_absolute(pidfile_path))
    log = str(resolve_absolute(logfile_path))
    db = str(resolve_absolute(db_path))
    prefix = build_service_command_prefix()
    for value in (cfg, pid, log, db, *prefix):
        assert_no_tilde(value)
    if system:
        if not user or not group:
            raise ValueError("System units require explicit non-root User= and Group=.")
        if user == "root" or group == "root":
            raise ValueError("Running systemd units as root (User=root) is strictly disallowed.")
    args = build_exec_args(cfg, pid, log, db, wrap_cmd, port)
    exec_start = shlex.join(prefix + args)
    env_lines = []
    for key in ("GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_APPLICATION_CREDENTIALS", "GEMINI_TIER", "PATH"):
        if key in env and env[key]:
            env_lines.append(f'Environment="{key}={env[key]}"')
    env_lines.append(f'Environment="BLACKWALL_DB_PATH={db}"')
    env_block = "\n".join(env_lines)
    env_file_block = "EnvironmentFile=-/etc/default/blackwall\n" if system else ""
    identity_block = f"User={user}\nGroup={group}\n" if system else ""
    dirs_block = (
        "RuntimeDirectory=blackwall\nStateDirectory=blackwall\nLogsDirectory=blackwall\n"
        if system
        else ""
    )
    content = f"""[Unit]
Description=Blackwall MCP Gateway
After=network.target
StartLimitBurst=5
StartLimitIntervalSec=60s

[Service]
Type=exec
PIDFile={pid}
ExecStart={exec_start}
Restart=on-failure
RestartSec=5s
MemoryHigh=320M
MemoryMax=350M
{identity_block}{dirs_block}{env_file_block}{env_block}

[Install]
WantedBy={"multi-user.target" if system else "default.target"}
"""
    assert_no_tilde(content)
    return content


def get_user_plist_path(home: Path | None = None) -> Path:
    """Return ``~/Library/LaunchAgents/com.blackwall.gateway.plist``."""
    base = home if home is not None else Path.home()
    return base / "Library" / "LaunchAgents" / LAUNCHD_PLIST_NAME


def get_user_systemd_path(home: Path | None = None) -> Path:
    """Return ``~/.config/systemd/user/blackwall.service``."""
    base = home if home is not None else Path.home()
    return base / ".config" / "systemd" / "user" / SYSTEMD_SERVICE_NAME


def get_system_systemd_path() -> Path:
    """Return ``/etc/systemd/system/blackwall.service``."""
    return Path("/etc/systemd/system") / SYSTEMD_SERVICE_NAME


def _default_user_paths(home: Path) -> tuple[Path, Path, Path, Path]:
    return (
        home / ".blackwall" / "gateway.yaml",
        home / ".blackwall" / "blackwall.pid",
        home / ".blackwall" / "blackwall.log",
        home / ".blackwall" / "threat_signatures.db",
    )


def collect_service_env(project: str, adc_path: Path | None) -> dict[str, str]:
    """Collect non-interactive service environment (R54)."""
    env: dict[str, str] = {
        "GCP_PROJECT": project,
        "GOOGLE_CLOUD_PROJECT": os.environ.get("GOOGLE_CLOUD_PROJECT", project),
        "GEMINI_TIER": "paid",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if adc_path is not None:
        env["GOOGLE_APPLICATION_CREDENTIALS"] = str(adc_path)
    elif os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        env["GOOGLE_APPLICATION_CREDENTIALS"] = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
    return env


def ensure_system_user(svc_user: str) -> None:
    """Verify or provision the systemd execution identity.

    For the dedicated ``blackwall`` account, attempts provisioning via
    ``useradd --system --home-dir /var/lib/blackwall --create-home`` when
    absent. Explicit ``--user``/``SUDO_USER`` identities must already exist.
    Provisioning failures are logged (non-root dev/CI) rather than fatal so
    unit generation remains testable without privileges.
    """
    try:
        pwd.getpwnam(svc_user)
        return
    except KeyError:
        pass
    if svc_user != DEDICATED_USER:
        raise ValueError(f"Service user '{svc_user}' does not exist on this host.")
    try:
        result = subprocess.run(
            [
                "useradd", "--system",
                "--home-dir", str(DEDICATED_HOME),
                "--create-home", DEDICATED_USER,
            ],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Dedicated service user '%s' absent and provisioning exited %s; "
                "create it with: useradd --system --home-dir %s --create-home %s",
                svc_user, result.returncode, DEDICATED_HOME, DEDICATED_USER,
            )
    except OSError as exc:
        logger.warning("Could not provision service user '%s': %s", svc_user, exc)


def _provision_system_credentials(
    src: Path | None, etc_root: Path | None = None
) -> Path | None:
    """Best-effort copy of ADC to ``/etc/blackwall/credentials.json`` (0600).

    Returns the provisioned path when it exists, else ``None``. ``etc_root``
    overrides the filesystem root for testing.
    """
    root = etc_root if etc_root is not None else Path("/")
    if etc_root is not None:
        target = root / "etc" / "blackwall" / "credentials.json"
    else:
        target = SYSTEM_CREDENTIALS_PATH
    if target.is_file():
        return target
    if src is None or not src.is_file():
        return target if target.is_file() else None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        try:
            target.chmod(0o600)
        except OSError:
            pass
        try:
            shutil.chown(str(target), user=DEDICATED_USER, group=DEDICATED_USER)
        except (LookupError, PermissionError, OSError):
            logger.debug("Skipping chown to %s (not available).", DEDICATED_USER)
        return target
    except OSError as exc:
        logger.warning("Could not provision system credentials at '%s': %s", target, exc)
        return target if target.is_file() else None


def install_service(
    config_path: str | None = None,
    wrap_cmd: str | None = None,
    project: str | None = None,
    credentials: str | None = None,
    system: bool = False,
    user: str | None = None,
    port: int = 9229,
    platform_override: str | None = None,
    home: Path | None = None,
    output_path: Path | None = None,
    etc_root: Path | None = None,
) -> Path:
    """Install the platform service definition and return its path.

    Raises ``ValueError`` (fail-fast) when GCP project or ADC is missing.
    """
    platform_name = detect_platform(platform_override)
    resolved_project = get_gcp_project(project)
    active_home = home if home is not None else Path.home()

    if system and platform_name != "linux":
        raise ValueError("--system is only supported on Linux systemd hosts.")

    if system:
        svc_user, svc_group = derive_system_user(user)
        ensure_system_user(svc_user)
        service_home = get_service_home(None, svc_user)
        adc = resolve_adc_path(credentials, service_home)
        if adc is None:
            raise ValueError(
                "ADC credentials not found: set GOOGLE_APPLICATION_CREDENTIALS, "
                f"ensure {service_home}/.config/gcloud/application_default_credentials.json "
                "exists, or pass --credentials <path>."
            )
        provisioned = _provision_system_credentials(adc, etc_root)
        effective_adc = provisioned if provisioned is not None and provisioned.is_file() else adc
        cfg = FHS_CONFIG
        pid = FHS_PID
        log = FHS_LOG
        db = FHS_DB
        env = collect_service_env(resolved_project, effective_adc)
        content = generate_systemd_unit(
            str(cfg), str(pid), str(log), str(db), wrap_cmd, env,
            system=True, user=svc_user, group=svc_group, port=port,
        )
        dest = output_path if output_path is not None else get_system_systemd_path()
    elif platform_name == "darwin":
        d_cfg, d_pid, d_log, d_db = _default_user_paths(active_home)
        cfg_p = resolve_absolute(config_path) if config_path else d_cfg.resolve()
        pid_p = d_pid.resolve()
        log_p = d_log.resolve()
        db_p = d_db.resolve()
        adc = resolve_adc_path(credentials, active_home)
        if adc is None:
            raise ValueError(
                "ADC credentials not found: set GOOGLE_APPLICATION_CREDENTIALS or run "
                "'gcloud auth application-default login'."
            )
        env = collect_service_env(resolved_project, adc)
        if wrap_cmd is None:
            wrap_or_cfg = str(cfg_p)
        else:
            wrap_or_cfg = wrap_cmd
        _ = wrap_or_cfg
        content = generate_launchd_plist(
            str(cfg_p), str(pid_p), str(log_p), str(db_p), wrap_cmd, env, port=port
        )
        dest = output_path if output_path is not None else get_user_plist_path(active_home)
    else:
        d_cfg, d_pid, d_log, d_db = _default_user_paths(active_home)
        cfg_p = resolve_absolute(config_path) if config_path else d_cfg.resolve()
        pid_p = d_pid.resolve()
        log_p = d_log.resolve()
        db_p = d_db.resolve()
        adc = resolve_adc_path(credentials, active_home)
        if adc is None:
            raise ValueError(
                "ADC credentials not found: set GOOGLE_APPLICATION_CREDENTIALS or run "
                "'gcloud auth application-default login'."
            )
        env = collect_service_env(resolved_project, adc)
        content = generate_systemd_unit(
            str(cfg_p), str(pid_p), str(log_p), str(db_p), wrap_cmd, env,
            system=False, port=port,
        )
        dest = output_path if output_path is not None else get_user_systemd_path(active_home)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    logger.info("Installed Blackwall service definition at %s", dest)
    return dest


def uninstall_service(
    system: bool = False,
    platform_override: str | None = None,
    home: Path | None = None,
    output_path: Path | None = None,
) -> bool:
    """Unload the service via launchctl/systemctl and remove its definition."""
    platform_name = detect_platform(platform_override)
    active_home = home if home is not None else Path.home()
    if output_path is not None:
        dest = output_path
    elif platform_name == "darwin":
        dest = get_user_plist_path(active_home)
    elif system:
        dest = get_system_systemd_path()
    else:
        dest = get_user_systemd_path(active_home)

    try:
        if platform_name == "darwin":
            subprocess.run(["launchctl", "unload", str(dest)], check=False)
        elif system:
            subprocess.run(["systemctl", "disable", "--now", "blackwall"], check=False)
        else:
            subprocess.run(["systemctl", "--user", "disable", "--now", "blackwall"], check=False)
    except OSError as exc:
        logger.warning("Service unload dispatch failed: %s", exc)
    try:
        if dest.exists():
            dest.unlink()
    except OSError as exc:
        logger.warning("Failed removing service file '%s': %s", dest, exc)
        return False
    return True


def start_service(system: bool = False, platform_override: str | None = None) -> bool:
    """Start the service via launchctl/systemctl."""
    platform_name = detect_platform(platform_override)
    if platform_name == "darwin":
        dest = get_user_plist_path()
        result = subprocess.run(["launchctl", "load", str(dest)], check=False)
    elif system:
        result = subprocess.run(["systemctl", "enable", "--now", "blackwall"], check=False)
    else:
        result = subprocess.run(["systemctl", "--user", "enable", "--now", "blackwall"], check=False)
    return result.returncode == 0


def stop_service(system: bool = False, platform_override: str | None = None) -> bool:
    """Stop the service via launchctl/systemctl."""
    platform_name = detect_platform(platform_override)
    if platform_name == "darwin":
        dest = get_user_plist_path()
        result = subprocess.run(["launchctl", "unload", str(dest)], check=False)
    elif system:
        result = subprocess.run(["systemctl", "stop", "blackwall"], check=False)
    else:
        result = subprocess.run(["systemctl", "--user", "stop", "blackwall"], check=False)
    return result.returncode == 0


def service_status(system: bool = False, platform_override: str | None = None) -> dict[str, str]:
    """Report service liveness via platform-native tools."""
    platform_name = detect_platform(platform_override)
    try:
        if platform_name == "darwin":
            dest = get_user_plist_path()
            result = subprocess.run(
                ["launchctl", "list", LAUNCHD_LABEL], capture_output=True, text=True, check=False
            )
            state = "Running" if result.returncode == 0 else "Stopped"
            return {"platform": "darwin", "state": state, "path": str(dest)}
        if system:
            result = subprocess.run(
                ["systemctl", "is-active", "blackwall"], capture_output=True, text=True, check=False
            )
        else:
            result = subprocess.run(
                ["systemctl", "--user", "is-active", "blackwall"],
                capture_output=True, text=True, check=False,
            )
        state = result.stdout.strip() if result.stdout else ("active" if result.returncode == 0 else "inactive")
        return {"platform": "linux", "state": state, "system": str(system)}
    except OSError as exc:
        return {"platform": platform_name, "state": f"unknown: {exc}"}


def configure_system_service(
    project: str | None = None,
    credentials_path: str | None = None,
    etc_root: Path | None = None,
) -> tuple[Path, Path]:
    """Write ``/etc/default/blackwall`` and provision credentials ``0600``.

    ``etc_root`` overrides the filesystem root for testing.
    """
    if not project and not credentials_path:
        raise ValueError("Nothing to configure: pass --project and/or --credentials.")
    root = etc_root if etc_root is not None else Path("/")
    default_dir = root / "etc" / "default" if etc_root is not None else SYSTEM_ENV_FILE.parent
    config_dir = root / "etc" / "blackwall" if etc_root is not None else SYSTEM_CREDENTIALS_PATH.parent
    default_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    env_file = default_dir / "blackwall"
    cred_file = config_dir / "credentials.json"

    lines: list[str] = []
    if env_file.exists():
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
    if project:
        resolved_project = project.strip()
        if not resolved_project:
            raise ValueError("Project ID cannot be empty.")
        lines = [ln for ln in lines if not ln.startswith("GCP_PROJECT=") and not ln.startswith("GOOGLE_CLOUD_PROJECT=")]
        lines.append(f"GCP_PROJECT={resolved_project}")
        lines.append(f"GOOGLE_CLOUD_PROJECT={resolved_project}")
        lines.append('GEMINI_TIER="paid"')
    env_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    if credentials_path:
        src = resolve_absolute(credentials_path)
        if not src.is_file():
            raise ValueError(f"Credentials file not found: {src}")
        data = src.read_bytes()
        import os as _os

        tmp = cred_file.with_suffix(".tmp")
        fd = _os.open(str(tmp), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
        try:
            with _os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        tmp.replace(cred_file)
        try:
            cred_file.chmod(0o600)
        except OSError:
            pass
        try:
            shutil.chown(str(cred_file), user=DEDICATED_USER, group=DEDICATED_USER)
        except (LookupError, PermissionError, OSError):
            logger.debug("Skipping chown to %s (not available in this environment).", DEDICATED_USER)
    return env_file, cred_file


def configure_user_service(
    project: str | None = None,
    credentials_path: str | None = None,
    home: Path | None = None,
    platform_override: str | None = None,
) -> tuple[Path | None, Path | None]:
    """Persist user-service environment settings and patch installed units.

    Writes ``~/.blackwall/service.env``, provisions
    ``~/.blackwall/credentials.json`` (0600) when ``credentials_path`` is
    given, and patches ``GCP_PROJECT``/``GOOGLE_APPLICATION_CREDENTIALS`` in
    the installed plist/unit when present. Accepts project-only,
    credentials-only, or both.
    """
    if not project and not credentials_path:
        raise ValueError("Nothing to configure: pass --project and/or --credentials.")
    active_home = home if home is not None else Path.home()
    blackwall_dir = active_home / ".blackwall"
    blackwall_dir.mkdir(parents=True, exist_ok=True)
    env_file = blackwall_dir / "service.env"
    cred_dest: Path | None = None

    if credentials_path:
        src = resolve_absolute(credentials_path)
        if not src.is_file():
            raise ValueError(f"Credentials file not found: {src}")
        cred_dest = blackwall_dir / "credentials.json"
        data = src.read_bytes()
        tmp = cred_dest.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        tmp.replace(cred_dest)
        try:
            cred_dest.chmod(0o600)
        except OSError:
            pass

    lines: list[str] = []
    if env_file.exists():
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
    if project:
        cleaned = project.strip()
        if not cleaned:
            raise ValueError("Project ID cannot be empty.")
        lines = [
            ln for ln in lines
            if not ln.startswith("GCP_PROJECT=") and not ln.startswith("GOOGLE_CLOUD_PROJECT=")
        ]
        lines.append(f"GCP_PROJECT={cleaned}")
        lines.append(f"GOOGLE_CLOUD_PROJECT={cleaned}")
        lines.append('GEMINI_TIER="paid"')
    if cred_dest is not None:
        lines = [ln for ln in lines if not ln.startswith("GOOGLE_APPLICATION_CREDENTIALS=")]
        lines.append(f"GOOGLE_APPLICATION_CREDENTIALS={cred_dest}")
    env_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    platform_name = detect_platform(platform_override)
    try:
        if platform_name == "darwin":
            plist = get_user_plist_path(active_home)
            if plist.is_file():
                _patch_plist_env(plist, project, cred_dest)
        else:
            unit = get_user_systemd_path(active_home)
            if unit.is_file():
                _patch_systemd_env(unit, project, cred_dest)
    except OSError as exc:
        logger.warning("Could not patch installed user service: %s", exc)
    return env_file, cred_dest


def _patch_plist_env(plist: Path, project: str | None, cred_dest: Path | None) -> None:
    """Update ``EnvironmentVariables`` entries in an installed plist."""
    import xml.etree.ElementTree as ET

    tree = ET.parse(str(plist))
    root = tree.getroot()
    main_dict = root.find("dict")
    if main_dict is None:
        return
    children = list(main_dict)
    env_dict = None
    for idx in range(0, len(children) - 1, 2):
        if children[idx].tag == "key" and children[idx].text == "EnvironmentVariables":
            if children[idx + 1].tag == "dict":
                env_dict = children[idx + 1]
    if env_dict is None:
        return
    entries = dict(zip(
        [e.text for e in env_dict.findall("key")],
        env_dict.findall("string"),
    ))
    updates: dict[str, str] = {}
    if project:
        updates["GCP_PROJECT"] = project.strip()
        updates["GOOGLE_CLOUD_PROJECT"] = project.strip()
        updates["GEMINI_TIER"] = "paid"
    if cred_dest is not None:
        updates["GOOGLE_APPLICATION_CREDENTIALS"] = str(cred_dest)
    for key, value in updates.items():
        if key in entries:
            entries[key].text = value
        else:
            key_el = ET.SubElement(env_dict, "key")
            key_el.text = key
            str_el = ET.SubElement(env_dict, "string")
            str_el.text = value
    tree.write(str(plist), encoding="utf-8", xml_declaration=True)


def _patch_systemd_env(unit: Path, project: str | None, cred_dest: Path | None) -> None:
    """Update ``Environment=`` directives in an installed user unit."""
    import re

    text = unit.read_text(encoding="utf-8")
    updates: dict[str, str] = {}
    if project:
        updates["GCP_PROJECT"] = project.strip()
        updates["GOOGLE_CLOUD_PROJECT"] = project.strip()
    if cred_dest is not None:
        updates["GOOGLE_APPLICATION_CREDENTIALS"] = str(cred_dest)
    for key, value in updates.items():
        pattern = re.compile(rf'^Environment="{re.escape(key)}=.*"$', re.MULTILINE)
        replacement = f'Environment="{key}={value}"'
        if pattern.search(text):
            text = pattern.sub(replacement, text)
        else:
            text = text.replace("[Service]", f"[Service]\n{replacement}", 1)
    unit.write_text(text, encoding="utf-8")
