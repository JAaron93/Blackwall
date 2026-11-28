"""macOS background service manager for the Blackwall MCP Gateway (FR-10 / TASK-F01).

Generates and manages a user-scoped ``launchd`` LaunchAgent at
``~/Library/LaunchAgents/com.blackwall.gateway.plist``.  All paths are resolved
to absolute filesystem paths at installation time because ``launchd`` does not
run a shell and therefore never expands ``~``.  Bearer secret values are never
embedded in the plist; they are provisioned into a ``0600`` dotenv file that the
gateway loads on startup.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from dotenv import load_dotenv

SERVICE_LABEL = "com.blackwall.gateway"
PLIST_FILENAME = f"{SERVICE_LABEL}.plist"
ENV_FILE_NAME = "gateway.env"
DEFAULT_PORT = 9229
GEMINI_TIER = "paid"
PROTECTED_ENV_KEYS = frozenset({"TYPESAFE_API_KEY"})
DEFAULT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class ServiceError(RuntimeError):
    """Raised when a service operation cannot be completed safely."""


def is_macos() -> bool:
    """Return True only on the launchd platform targeted by FR-10."""
    return sys.platform == "darwin"


def _absolute_path(value: str | Path, home: Path | None = None) -> Path:
    """Expand user-relative paths against ``home`` and return a resolved path.

    A literal ``~`` is rejected after expansion so that generated service
    definitions can never carry an unexpanded tilde into ``launchd``.
    """
    text = os.fspath(value)
    if text == "~" or text.startswith("~/"):
        base = home if home is not None else Path.home()
        text = str(base) if text == "~" else str(base / text[2:])
    if "~" in text:
        raise ServiceError(f"Path contains an unexpanded '~' character: {text}")
    return Path(text).expanduser().resolve()


@dataclass(frozen=True)
class ServicePaths:
    """All absolute filesystem paths used by the LaunchAgent."""

    home: Path
    blackwall_home: Path
    launch_agents_dir: Path
    plist_path: Path
    env_file_path: Path
    config_path: Path
    pid_path: Path
    log_path: Path
    db_path: Path


def resolve_service_paths(
    config: str | Path | None = None,
    pidfile: str | Path | None = None,
    logfile: str | Path | None = None,
    db: str | Path | None = None,
    home: str | Path | None = None,
) -> ServicePaths:
    """Resolve every service path to an absolute path at install time."""
    base = _absolute_path(home) if home is not None else Path.home().resolve()
    blackwall_home = base / ".blackwall"
    launch_agents = base / "Library" / "LaunchAgents"
    return ServicePaths(
        home=base,
        blackwall_home=blackwall_home,
        launch_agents_dir=launch_agents,
        plist_path=launch_agents / PLIST_FILENAME,
        env_file_path=blackwall_home / ENV_FILE_NAME,
        config_path=_absolute_path(config or blackwall_home / "gateway.yaml", base),
        pid_path=_absolute_path(pidfile or blackwall_home / "blackwall.pid", base),
        log_path=_absolute_path(logfile or blackwall_home / "blackwall.log", base),
        db_path=_absolute_path(db or blackwall_home / "threat_signatures.db", base),
    )


def resolve_project(project: str | None = None, env: Mapping[str, str] | None = None) -> str:
    """Resolve the GCP project ID, failing fast when none is configured."""
    source = os.environ if env is None else env
    resolved = (
        project
        or source.get("GCP_PROJECT")
        or source.get("GOOGLE_CLOUD_PROJECT")
        or ""
    ).strip()
    if not resolved:
        raise ServiceError(
            "GCP_PROJECT is required to install the Blackwall service. "
            "Set GCP_PROJECT (or GOOGLE_CLOUD_PROJECT) or pass --project <id>."
        )
    return resolved


def resolve_credentials(
    explicit: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Resolve user ADC, falling back to the standard gcloud ADC location."""
    source = os.environ if env is None else env
    base = home if home is not None else Path.home().resolve()
    candidate = explicit or source.get("GOOGLE_APPLICATION_CREDENTIALS")
    if candidate:
        path = _absolute_path(candidate, base)
    else:
        path = _absolute_path(
            base / ".config" / "gcloud" / "application_default_credentials.json", base
        )
    if not path.is_file():
        raise ServiceError(
            f"GCP Application Default Credentials (ADC) not found at {path}. "
            "Run 'gcloud auth application-default login', set "
            "GOOGLE_APPLICATION_CREDENTIALS, or pass --credentials <path>."
        )
    return path


def resolve_executable() -> list[str]:
    """Return an absolute command prefix for the supervised gateway process."""
    binary = shutil.which("blackwall")
    if binary:
        return [str(_absolute_path(binary))]
    return [str(_absolute_path(sys.executable)), "-m", "blackwall.cli"]


def resolve_wrap_command(wrap: str, home: Path) -> str:
    """Resolve the upstream executable and relative paths in a --wrap command.

    ``launchd`` runs with a different working directory, so relative upstream
    executables/scripts from the installation directory must be made absolute
    at install time. Bare command names are resolved via ``PATH`` when possible.
    """
    parts = shlex.split(wrap)
    if not parts:
        raise ServiceError("The --wrap command must not be empty")
    executable = parts[0]
    if executable.startswith(("/", "./", "../", "~")):
        parts[0] = str(_absolute_path(executable, home))
    else:
        located = shutil.which(executable)
        if located:
            parts[0] = str(_absolute_path(located, home))
    for index, token in enumerate(parts[1:], start=1):
        if token.startswith(("./", "../", "~")):
            parts[index] = str(_absolute_path(token, home))
        elif "~" in token:
            raise ServiceError(f"Unexpanded '~' in --wrap argument: {token}")
    return shlex.join(parts)


def _resolved_search_path(value: str | None, home: Path) -> str:
    """Expand every PATH entry so no tilde survives into the plist."""
    if not value:
        return DEFAULT_PATH
    return os.pathsep.join(
        str(_absolute_path(entry, home)) if entry else entry
        for entry in value.split(os.pathsep)
    )


@dataclass(frozen=True)
class ServiceConfig:
    """Input to LaunchAgent plist generation."""

    paths: ServicePaths
    project_id: str
    credentials_path: Path
    env: Mapping[str, str]
    working_dir: Path
    wrap: str | None = None
    port: int = DEFAULT_PORT
    log_level: str = "INFO"

    def launch_arguments(self) -> list[str]:
        """Build the absolute ``ProgramArguments`` for ``blackwall serve``."""
        args = [
            *resolve_executable(),
            "serve",
            "--foreground",
            "--transport",
            "http",
            "--port",
            str(self.port),
            "--config",
            str(self.paths.config_path),
            "--pidfile",
            str(self.paths.pid_path),
            "--logfile",
            str(self.paths.log_path),
            "--db",
            str(self.paths.db_path),
            "--log-level",
            self.log_level,
        ]
        if self.wrap:
            args.extend(["--wrap", resolve_wrap_command(self.wrap, self.paths.home)])
        return args


def build_service_config(
    *,
    config: str | Path | None = None,
    wrap: str | None = None,
    project: str | None = None,
    credentials: str | Path | None = None,
    pidfile: str | Path | None = None,
    logfile: str | Path | None = None,
    db: str | Path | None = None,
    port: int = DEFAULT_PORT,
    home: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> ServiceConfig:
    """Validate install-time inputs and produce an immutable service config."""
    source = dict(os.environ if env is None else env)
    paths = resolve_service_paths(config, pidfile, logfile, db, home)
    project_id = resolve_project(project, source)
    credentials_path = resolve_credentials(credentials, source, paths.home)
    # A wrapped upstream resolves relative arguments against the installation
    # directory, so preserve that cwd instead of the home directory default.
    working_dir = Path.cwd().resolve() if wrap else paths.home
    return ServiceConfig(
        paths=paths,
        project_id=project_id,
        credentials_path=credentials_path,
        env=source,
        working_dir=working_dir,
        wrap=wrap,
        port=port,
    )


def build_plist(config: ServiceConfig) -> dict[str, Any]:
    """Build the LaunchAgent dictionary with supervision and injected env vars."""
    environment = {
        "GCP_PROJECT": config.project_id,
        "GOOGLE_CLOUD_PROJECT": config.project_id,
        "GOOGLE_APPLICATION_CREDENTIALS": str(config.credentials_path),
        "GEMINI_TIER": GEMINI_TIER,
        "PATH": _resolved_search_path(config.env.get("PATH"), config.paths.home),
    }
    return {
        "Label": SERVICE_LABEL,
        "ProgramArguments": config.launch_arguments(),
        "EnvironmentVariables": environment,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "StandardOutPath": str(config.paths.log_path),
        "StandardErrorPath": str(config.paths.log_path),
        "WorkingDirectory": str(config.working_dir),
    }


def generate_plist(config: ServiceConfig) -> str:
    """Serialize a validated service config to XML plist text.

    Defense in depth: if a protected secret value ever reaches this layer it is
    rejected rather than written into an inspectable plist.
    """
    xml = plistlib.dumps(build_plist(config), fmt=plistlib.FMT_XML, sort_keys=True).decode(
        "utf-8"
    )
    for key in PROTECTED_ENV_KEYS:
        secret = config.env.get(key)
        if secret and secret in xml:
            raise ServiceError(f"{key} must never be embedded in a LaunchAgent plist")
    return xml


def write_plist(config: ServiceConfig) -> Path:
    """Write the validated plist to the macOS LaunchAgents directory."""
    config.paths.launch_agents_dir.mkdir(parents=True, exist_ok=True)
    # launchd opens stdout/stderr before the gateway process starts, so these
    # directories must already exist at install time.
    for path in (
        config.paths.log_path.parent,
        config.paths.pid_path.parent,
        config.paths.db_path.parent,
        config.paths.config_path.parent,
    ):
        path.mkdir(parents=True, exist_ok=True)
    config.paths.plist_path.write_text(generate_plist(config), encoding="utf-8")
    config.paths.plist_path.chmod(0o644)
    return config.paths.plist_path


def provision_protected_env(
    key: str,
    value: str,
    env_path: str | Path | None = None,
) -> Path:
    """Persist a bearer secret exclusively to a ``0600`` dotenv file."""
    if key not in PROTECTED_ENV_KEYS:
        raise ServiceError(f"Refusing to store unsupported protected key: {key}")
    if not value or not value.strip() or any(char in value for char in "\r\n"):
        raise ServiceError(f"Invalid value supplied for {key}")
    path = (
        _absolute_path(env_path)
        if env_path is not None
        else Path.home().resolve() / ".blackwall" / ENV_FILE_NAME
    )
    entries: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, stored = stripped.split("=", 1)
            entries[name.strip()] = stored
    entries[key] = value

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".gateway-env-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for name, stored in entries.items():
                handle.write(f"{name}={stored}\n")
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    os.chmod(path, 0o600)
    return path


def load_protected_env(env_path: str | Path | None = None) -> bool:
    """Load the protected dotenv file at daemon startup (launchd has no EnvironmentFile)."""
    path = (
        _absolute_path(env_path)
        if env_path is not None
        else Path.home().resolve() / ".blackwall" / ENV_FILE_NAME
    )
    if not path.is_file():
        return False
    load_dotenv(dotenv_path=str(path), override=False)
    return True


def install_service(config: ServiceConfig, typesafe_key: str | None = None) -> Path:
    """Install the LaunchAgent and, when present, protect the TypeSafe key."""
    # Provision the protected secret first: a failed secret write must never
    # leave behind a LaunchAgent that can start without its credentials.
    if typesafe_key:
        provision_protected_env("TYPESAFE_API_KEY", typesafe_key, config.paths.env_file_path)
    return write_plist(config)


def launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke launchctl with an absolute binary path and bounded execution."""
    return subprocess.run(
        ["/bin/launchctl", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )


def _domain_target() -> str:
    getuid = getattr(os, "getuid", None)
    uid = getuid() if getuid is not None else 0
    return f"gui/{uid}"


def _default_plist_path() -> Path:
    return Path.home().resolve() / "Library" / "LaunchAgents" / PLIST_FILENAME


def start_service(plist_path: str | Path | None = None) -> None:
    """Bootstrap the LaunchAgent into the current GUI domain."""
    path = _absolute_path(plist_path) if plist_path is not None else _default_plist_path()
    if not path.is_file():
        raise ServiceError(f"Blackwall service is not installed at {path}.")
    result = launchctl("bootstrap", _domain_target(), str(path))
    if result.returncode != 0:
        raise ServiceError(f"launchctl bootstrap failed: {result.stderr.strip()}")


def stop_service() -> None:
    """Boot the LaunchAgent out of the current GUI domain."""
    result = launchctl("bootout", f"{_domain_target()}/{SERVICE_LABEL}")
    if result.returncode != 0:
        raise ServiceError(f"launchctl bootout failed: {result.stderr.strip()}")


def service_status() -> subprocess.CompletedProcess[str]:
    """Query launchctl for the service's current state."""
    return launchctl("list", SERVICE_LABEL)


_NOT_LOADED_MESSAGES = (
    "could not find specified service",
    "no such process",
    "not loaded",
    "service does not exist",
)


def _job_already_unloaded(message: str) -> bool:
    lowered = message.lower()
    return any(fragment in lowered for fragment in _NOT_LOADED_MESSAGES)


def uninstall_service(plist_path: str | Path | None = None) -> bool:
    """Unload the LaunchAgent and remove its plist; no-op when not installed."""
    path = _absolute_path(plist_path) if plist_path is not None else _default_plist_path()
    if not path.is_file():
        return False
    result = launchctl("bootout", _domain_target(), str(path))
    # A job stopped earlier (or never bootstrapped) is already unloaded; that
    # must not block plist removal. Genuine failures are still surfaced.
    if result.returncode != 0 and not _job_already_unloaded(result.stderr):
        raise ServiceError(f"launchctl bootout failed: {result.stderr.strip()}")
    path.unlink()
    return True


def configure_service(
    *,
    project: str | None = None,
    credentials: str | Path | None = None,
    typesafe_key: str | None = None,
    home: str | Path | None = None,
) -> Path:
    """Update project IDs / credential paths and the protected secret file."""
    paths = resolve_service_paths(home=home)
    plist_path = paths.plist_path
    if not plist_path.is_file():
        raise ServiceError(f"Blackwall service is not installed at {plist_path}.")
    data = plistlib.loads(plist_path.read_bytes())
    env_vars = dict(data.get("EnvironmentVariables", {}))

    if project is not None:
        resolved_project = resolve_project(project)
        env_vars["GCP_PROJECT"] = resolved_project
        env_vars["GOOGLE_CLOUD_PROJECT"] = resolved_project
    if credentials is not None:
        env_vars["GOOGLE_APPLICATION_CREDENTIALS"] = str(
            resolve_credentials(credentials, home=paths.home)
        )

    data["EnvironmentVariables"] = env_vars
    plist_path.write_bytes(
        plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=True)
    )
    plist_path.chmod(0o644)
    if typesafe_key:
        provision_protected_env("TYPESAFE_API_KEY", typesafe_key, paths.env_file_path)
    return plist_path
