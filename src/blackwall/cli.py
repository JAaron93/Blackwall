"""Blackwall Native CLI Tool Suite (Track E).

Provides interactive terminal commands:
- `blackwall check <indicator>` with automatic type detection
- `blackwall threat-intel lookup <indicator>`
- `blackwall threat-intel pulse <pulse_id>`
- `blackwall threat-intel cache status|clear`
- `blackwall threat-intel providers`
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import logging
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import click
from rich import box
from rich.console import Console
from rich.table import Table

try:
    import google.auth
    import google.auth.exceptions
except ImportError:
    google.auth = None  # type: ignore[assignment]

from blackwall.db.repository import SQLiteThreatRepository
from blackwall.gateway.daemon import (
    daemonize,
    is_blackwall_process,
    is_process_alive,
    read_pid_file,
    remove_pid_file,
    stop_daemon,
    write_pid_file,
)
from blackwall.gateway.server import MCPGatewayServer
from blackwall.gateway.upstream import UpstreamManager
from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelResponse,
)
from blackwall.threat_intel.orchestrator import ThreatIntelOrchestrator

logger = logging.getLogger("blackwall.cli")
console = Console()


def detect_indicator_type(indicator: str) -> ThreatIndicatorType:
    """Automatically classifies indicator string into ThreatIndicatorType.

    Auto-classifies IPv4, IPv6, URL, File Hashes (MD5, SHA1, SHA256), and Domains.
    Raises ValueError if classification fails.
    """
    indicator = indicator.strip()
    if not indicator:
        raise ValueError("Indicator cannot be empty")

    # 1. IP Address check (IPv4 and IPv6)
    try:
        ip = ipaddress.ip_address(indicator)
        if isinstance(ip, ipaddress.IPv4Address):
            return ThreatIndicatorType.IPV4
        elif isinstance(ip, ipaddress.IPv6Address):
            return ThreatIndicatorType.IPV6
    except ValueError:
        pass

    # 2. URL check (starts with protocol scheme)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", indicator):
        return ThreatIndicatorType.URL

    # 3. File Hash check (MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex)
    if (
        re.match(r"^[a-fA-F0-9]{32}$", indicator)
        or re.match(r"^[a-fA-F0-9]{40}$", indicator)
        or re.match(r"^[a-fA-F0-9]{64}$", indicator)
    ):
        return ThreatIndicatorType.FILE_HASH

    # 4. Domain check (FQDN structure)
    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if re.match(domain_pattern, indicator) and len(indicator) <= 253:
        return ThreatIndicatorType.DOMAIN

    raise ValueError(f"Could not automatically detect indicator type for: '{indicator}'")


def compute_verdict(response: ThreatIntelResponse) -> str:
    """Calculates standardized ALLOW / WARN / BLOCK verdict based on risk and pulse data."""
    if response.risk_score >= 0.50 or (
        response.is_malicious and response.risk_score >= 0.25
    ):
        return "BLOCK"
    elif response.risk_score >= 0.20 or response.is_malicious:
        return "WARN"
    return "ALLOW"


async def _safe_close_repo(
    repo: Any, orchestrator: Optional[Any] = None
) -> None:
    """Safely flush orchestrator metrics and close repository if callable and awaitable."""
    if orchestrator is not None and hasattr(orchestrator, "flush_metrics"):
        try:
            res = orchestrator.flush_metrics()
            if inspect.isawaitable(res):
                await res
        except Exception:
            pass
    if repo is None:
        return
    close_fn = getattr(repo, "close", None)
    if callable(close_fn):
        res = close_fn()
        if inspect.isawaitable(res):
            await res


def get_orchestrator(db_path: str = "./blackwall.db") -> ThreatIntelOrchestrator:
    """Factory helper to build and return a configured ThreatIntelOrchestrator."""
    repo = SQLiteThreatRepository(db_path=db_path)
    return ThreatIntelOrchestrator(repository=repo)


def _render_check_table(
    response: ThreatIntelResponse,
    verdict: str,
    indicator: str,
    ind_type: ThreatIndicatorType,
) -> None:
    """Renders formatted rich table for blackwall check command."""
    table = Table(
        title="Blackwall Threat Intelligence Inspection",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("Indicator", style="bold cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Verdict", justify="center")
    table.add_column("Risk Score", justify="right")
    table.add_column("Pulses", justify="right")
    table.add_column("Categories / Families", style="yellow")
    table.add_column("Provider", style="green")

    if verdict == "BLOCK":
        verdict_str = "[bold red]BLOCK[/bold red]"
    elif verdict == "WARN":
        verdict_str = "[bold yellow]WARN[/bold yellow]"
    else:
        verdict_str = "[bold green]ALLOW[/bold green]"

    families_cats = ", ".join(
        response.malware_families + response.threat_categories
    ) or "None"

    table.add_row(
        indicator,
        ind_type.value if hasattr(ind_type, "value") else str(ind_type),
        verdict_str,
        f"{response.risk_score:.2f}",
        str(response.pulse_count),
        families_cats,
        response.provider_name,
    )
    console.print(table)


def _render_check_json(
    response: ThreatIntelResponse,
    verdict: str,
    indicator: str,
    ind_type: ThreatIndicatorType,
) -> None:
    """Renders structured JSON for blackwall check command."""
    payload = {
        "indicator": indicator,
        "indicator_type": (
            ind_type.value if hasattr(ind_type, "value") else str(ind_type)
        ),
        "verdict": verdict,
        "risk_score": response.risk_score,
        "is_malicious": response.is_malicious,
        "pulse_count": response.pulse_count,
        "detection_count": response.detection_count,
        "threat_categories": response.threat_categories,
        "malware_families": response.malware_families,
        "references": response.references,
        "provider_name": response.provider_name,
        "cached": response.cached,
    }
    console.print(json.dumps(payload, indent=2))


@click.group()
@click.option(
    "--db-path",
    default=None,
    help="Path to SQLite threat database.",
)
@click.pass_context
def cli(ctx: click.Context, db_path: Optional[str]) -> None:
    """Blackwall Agentic Security Firewall CLI."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db_path or os.environ.get("BW_DB_PATH", "./blackwall.db")


@cli.command(name="check")
@click.argument("indicator")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (table or json).",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass local threat intelligence cache.",
)
@click.option(
    "--provider",
    "-p",
    default=None,
    help="Target specific threat intel provider.",
)
@click.option(
    "--type",
    "-t",
    "indicator_type_arg",
    default=None,
    help="Explicit indicator type override (ipv4, ipv6, domain, url, file_hash).",
)
@click.pass_context
def check_command(
    ctx: click.Context,
    indicator: str,
    output_format: str,
    no_cache: bool,
    provider: Optional[str],
    indicator_type_arg: Optional[str],
) -> None:
    """Inspect an indicator with automatic type detection and threat intelligence."""
    # Resolve indicator type
    if indicator_type_arg:
        arg_clean = indicator_type_arg.strip().upper()
        if arg_clean == "HASH":
            arg_clean = "FILE_HASH"
        try:
            ind_type = ThreatIndicatorType(arg_clean)
        except ValueError:
            try:
                ind_type = ThreatIndicatorType[arg_clean]
            except KeyError:
                raise click.BadParameter(
                    f"Invalid indicator type: {indicator_type_arg}"
                )
    else:
        try:
            ind_type = detect_indicator_type(indicator)
        except ValueError as e:
            raise click.ClickException(str(e))

    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> ThreatIntelResponse:
        try:
            return await orchestrator.lookup(
                indicator=indicator,
                indicator_type=ind_type,
                no_cache=no_cache,
                provider=provider,
            )
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        response = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Threat intelligence lookup failed: {exc}")

    verdict = compute_verdict(response)

    if output_format.lower() == "json":
        _render_check_json(response, verdict, indicator, ind_type)
    else:
        _render_check_table(response, verdict, indicator, ind_type)


@cli.group(name="threat-intel")
def threat_intel_group() -> None:
    """Threat intelligence feed and cache management commands."""
    pass


@threat_intel_group.command(name="lookup")
@click.argument("indicator")
@click.option(
    "--type",
    "-t",
    "indicator_type_arg",
    default=None,
    help="Explicit indicator type override.",
)
@click.option(
    "--provider",
    "-p",
    default=None,
    help="Target provider (otx, abuseipdb, abusech, all).",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass threat intelligence cache.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (table or json).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show verbose details including references and engine detections.",
)
@click.pass_context
def lookup_command(
    ctx: click.Context,
    indicator: str,
    indicator_type_arg: Optional[str],
    provider: Optional[str],
    no_cache: bool,
    output_format: str,
    verbose: bool,
) -> None:
    """Query threat intelligence for a specific indicator."""
    if indicator_type_arg:
        arg_clean = indicator_type_arg.strip().upper()
        if arg_clean == "HASH":
            arg_clean = "FILE_HASH"
        try:
            ind_type = ThreatIndicatorType(arg_clean)
        except ValueError:
            try:
                ind_type = ThreatIndicatorType[arg_clean]
            except KeyError:
                raise click.BadParameter(
                    f"Invalid indicator type: {indicator_type_arg}"
                )
    else:
        try:
            ind_type = detect_indicator_type(indicator)
        except ValueError as e:
            raise click.ClickException(str(e))

    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> ThreatIntelResponse:
        try:
            return await orchestrator.lookup(
                indicator=indicator,
                indicator_type=ind_type,
                no_cache=no_cache,
                provider=provider,
            )
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        response = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Threat intelligence lookup failed: {exc}")

    verdict = compute_verdict(response)

    if output_format.lower() == "json":
        _render_check_json(response, verdict, indicator, ind_type)
    else:
        _render_check_table(response, verdict, indicator, ind_type)
        if verbose:
            if response.references:
                console.print(
                    "\n[bold underline]External References:[/bold underline]"
                )
                for ref in response.references:
                    console.print(f"  • {ref}")
            if response.threat_categories:
                console.print(
                    f"\n[bold]Threat Categories:[/bold] {', '.join(response.threat_categories)}"
                )
            if response.malware_families:
                console.print(
                    f"[bold]Malware Families:[/bold] {', '.join(response.malware_families)}"
                )


@threat_intel_group.command(name="pulse")
@click.argument("pulse_id")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (table or json).",
)
@click.pass_context
def pulse_command(
    ctx: click.Context,
    pulse_id: str,
    output_format: str,
) -> None:
    """Fetch detailed threat pulse metadata and IOC references from AlienVault OTX."""
    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> Dict[str, Any]:
        try:
            return await orchestrator.get_pulse(pulse_id)
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        pulse_data = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Failed fetching pulse {pulse_id}: {exc}")

    if output_format.lower() == "json":
        console.print(json.dumps(pulse_data, indent=2))
        return

    table = Table(
        title=f"OTX Threat Pulse: {pulse_data.get('name', pulse_id)}",
        box=box.ROUNDED,
        header_style="bold blue",
    )
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Pulse ID", str(pulse_data.get("id", pulse_id)))
    table.add_row("Name", str(pulse_data.get("name", "N/A")))
    table.add_row("Description", str(pulse_data.get("description", "N/A"))[:120])
    table.add_row("Author", str(pulse_data.get("author_name", "N/A")))
    table.add_row("Created", str(pulse_data.get("created", "N/A")))
    table.add_row("Modified", str(pulse_data.get("modified", "N/A")))
    table.add_row("Adversary", str(pulse_data.get("adversary", "N/A")))

    tags = pulse_data.get("tags", [])
    table.add_row(
        "Tags", ", ".join(tags) if isinstance(tags, list) else str(tags)
    )

    malware = pulse_data.get("malware_families", [])
    table.add_row(
        "Malware Families",
        ", ".join(malware) if isinstance(malware, list) else str(malware),
    )

    refs = pulse_data.get("references", [])
    if isinstance(refs, list) and refs:
        table.add_row("References", "\n".join(refs[:5]))
    else:
        table.add_row("References", "None")

    indicator_count = pulse_data.get(
        "indicator_count", len(pulse_data.get("indicators", []))
    )
    table.add_row("IOC Count", str(indicator_count))

    console.print(table)


@threat_intel_group.group(name="cache")
def cache_group() -> None:
    """Local SQLite threat intelligence cache operations."""
    pass


@cache_group.command(name="status")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (table or json).",
)
@click.pass_context
def cache_status_command(ctx: click.Context, output_format: str) -> None:
    """Display volume, expired records, and hit statistics for threat_intel_cache."""
    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> Dict[str, Any]:
        try:
            return await orchestrator.get_cache_stats()
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        stats = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Failed querying cache status: {exc}")

    if output_format.lower() == "json":
        console.print(json.dumps(stats, indent=2))
        return

    table = Table(
        title="SQLite Threat Intelligence Cache Status",
        box=box.ROUNDED,
        header_style="bold green",
    )
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", justify="right", style="white")

    total = stats.get("total_entries", 0)
    active = stats.get("active_entries", 0)
    expired = stats.get("expired_entries", 0)
    malicious = stats.get("malicious_entries", 0)
    size_bytes = stats.get("size_bytes", 0)
    hits = stats.get("hits", 0)
    misses = stats.get("misses", 0)
    total_queries = hits + misses
    hit_rate = (hits / total_queries * 100.0) if total_queries > 0 else 0.0

    table.add_row("Total Cached Entries", str(total))
    table.add_row("Active Entries (Valid TTL)", str(active))
    table.add_row("Expired Entries (Pending Eviction)", str(expired))
    table.add_row("Malicious Indicators", str(malicious))
    table.add_row(
        "Payload Storage Size",
        f"{size_bytes} bytes ({size_bytes / 1024.0:.2f} KB)",
    )
    table.add_row("Cache Hits", str(hits))
    table.add_row("Cache Misses", str(misses))
    table.add_row("Hit Rate", f"{hit_rate:.1f}%")

    console.print(table)


@cache_group.command(name="clear")
@click.option(
    "--expired-only",
    is_flag=True,
    default=False,
    help="Only purge expired entries beyond their TTL.",
)
@click.pass_context
def cache_clear_command(ctx: click.Context, expired_only: bool) -> None:
    """Evict cached threat intelligence records deterministically."""
    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> int:
        try:
            return await orchestrator.clear_cache(expired_only=expired_only)
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        count = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Failed clearing cache: {exc}")

    scope = "expired" if expired_only else "all"
    console.print(f"[bold green]Successfully evicted {count} {scope} cache records.[/bold green]")


@threat_intel_group.command(name="providers")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format (table or json).",
)
@click.pass_context
def providers_command(ctx: click.Context, output_format: str) -> None:
    """Inspect configured threat intelligence providers, health status, and quotas."""
    db_path = ctx.obj.get("db_path", "./blackwall.db")
    orchestrator = get_orchestrator(db_path=db_path)

    async def _run() -> list[dict[str, Any]]:
        try:
            providers = orchestrator.get_providers(include_on_demand=True)
            results = []
            for p in providers:
                # Unwrap CircuitBreakerProvider if needed for inspection
                underlying = getattr(p, "provider", p)
                name = getattr(p, "name", "unknown")

                # Health check
                try:
                    healthy = await p.is_healthy()
                    health_str = "Healthy" if healthy else "Degraded"
                except Exception:
                    health_str = "Down"

                # Remaining budget
                try:
                    budget = p.get_remaining_budget()
                except Exception:
                    budget = 0

                # Circuit breaker state
                circuit_state = (
                    getattr(p, "state", None)
                    or getattr(underlying, "circuit_state", None)
                    or "CLOSED"
                )
                if hasattr(circuit_state, "value"):
                    circuit_state = circuit_state.value

                # Supported indicators
                ind_types = [
                    (i.value if hasattr(i, "value") else str(i))
                    for i in getattr(p, "supported_indicators", [])
                ]

                # Credential check without leaking actual secrets
                has_key = bool(
                    getattr(underlying, "api_key", None)
                    or getattr(underlying, "auth_key", None)
                )
                auth_status = "Authenticated" if has_key else "Unauthenticated / Public"

                results.append(
                    {
                        "name": name,
                        "health": health_str,
                        "circuit_state": str(circuit_state),
                        "remaining_budget": budget,
                        "supported_indicators": ind_types,
                        "auth_status": auth_status,
                    }
                )
            return results
        finally:
            await _safe_close_repo(orchestrator.repository, orchestrator=orchestrator)

    try:
        providers_data = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(f"Failed inspecting providers: {exc}")

    if output_format.lower() == "json":
        console.print(json.dumps(providers_data, indent=2))
        return

    table = Table(
        title="Configured Threat Intelligence Providers",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Provider", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Circuit State", justify="center")
    table.add_column("Remaining Budget", justify="right", style="green")
    table.add_column("Auth Status", style="yellow")
    table.add_column("Supported Indicators", style="cyan")

    for p in providers_data:
        status_style = (
            "[bold green]Healthy[/bold green]"
            if p["health"] == "Healthy"
            else "[bold red]Degraded[/bold red]"
        )
        circuit_style = (
            "[green]CLOSED[/green]"
            if p["circuit_state"] == "CLOSED"
            else f"[bold red]{p['circuit_state']}[/bold red]"
        )
        table.add_row(
            p["name"],
            status_style,
            circuit_style,
            str(p["remaining_budget"]),
            p["auth_status"],
            ", ".join(p["supported_indicators"]),
        )

    console.print(table)


def validate_gcp_credentials() -> tuple[bool, str]:
    """Validates GCP Vertex AI project ID and Application Default Credentials (ADC)."""
    skip = os.environ.get("BW_SKIP_GCP_CHECK", "").lower() in ("1", "true", "yes")
    if skip:
        return True, ""

    project = os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        return (
            False,
            "Missing GCP Project: Neither GCP_PROJECT nor GOOGLE_CLOUD_PROJECT is set. "
            "Export your GCP Project ID to start Blackwall in GCP Vertex AI Mode.",
        )

    creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if creds_path:
        path_obj = Path(creds_path)
        if not path_obj.exists():
            return (
                False,
                f"GOOGLE_APPLICATION_CREDENTIALS file not found: {creds_path}",
            )
        return True, ""

    default_adc = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
    if default_adc.exists():
        return True, ""

    # Check ambient ADC (Compute Engine, Cloud Run, GKE metadata service) via google.auth if installed
    if google.auth is not None:
        try:
            creds, _ = google.auth.default()
            if creds is not None:
                return True, ""
        except (google.auth.exceptions.DefaultCredentialsError, Exception):
            pass

    return (
        False,
        "GCP Application Default Credentials (ADC) not found. "
        "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.",
    )


DEFAULT_POLICY_YAML = """# Blackwall Security Policy Configuration
version: "1.0.0"
global:
  threatThreshold: 0.75
  quarantineThreshold: 0.50
  enableStructuralGating: true
  enableSemanticGating: true

environmentRoles:
  sandbox:
    allowedTools: ["read_file", "file_read", "list_dir"]
    blockedTools: []
    requireSemanticReview: true
    maxThreatScore: 0.80
  development:
    allowedTools: ["read_file", "file_read", "list_dir"]
    blockedTools: []
    requireSemanticReview: true
    maxThreatScore: 0.70
  staging:
    allowedTools: ["read_file", "file_read", "list_dir"]
    blockedTools: ["execute_bash", "execute_shell", "run_python", "install_package"]
    requireSemanticReview: true
    maxThreatScore: 0.60
  production:
    allowedTools: []
    blockedTools: ["execute_bash", "execute_shell", "run_python", "install_package"]
    requireSemanticReview: true
    maxThreatScore: 0.50

structuralRules:
  - ruleId: "rule-block-dangerous-tools-prod-staging"
    condition: "(toolName == 'execute_bash' or toolName == 'execute_shell' or toolName == 'run_python' or toolName == 'install_package') and (environmentRole == 'production' or environmentRole == 'staging')"
    action: BLOCK
    priority: 1
    enabled: true
  - ruleId: "rule-escalate-write-operations"
    condition: "toolName == 'write_file'"
    action: ESCALATE_TO_SEMANTIC
    priority: 2
    enabled: true

semanticGuidelines:
  - "Prevent arbitrary command execution or privilege escalation."
  - "Block unauthorized file system modifications or data exfiltration."

mcpServers:
  threatIntel:
    enabled: true
    url: "https://otx.alienvault.com"
    apiKey: null
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 5000
  codebaseMemory:
    enabled: true
    url: "http://localhost:8080"
    apiKey: null
    cacheEnabled: true
    cacheTTL: 3600
    timeout: 5000

threatSignatureGraph:
  dbPath: "./threat_signatures.db"
  walMode: true
  maxConnections: 5
  similarityThreshold: 0.75
  ttlSeconds: 86400
  maxSignatures: 10000
  embeddingDimension: 384
  batchSize: 900
"""

DEFAULT_GATEWAY_YAML = """# Blackwall MCP Gateway Upstream Routing Configuration
upstream_servers:
  - name: local_tools
    command: "python -m blackwall.tools"
    transport: stdio
"""


@cli.command(name="version")
def version_command() -> None:
    """Print the Blackwall version."""
    console.print("Blackwall v2.0.0 (MCP Gateway)")


@cli.command(name="init")
@click.option(
    "--dir",
    "target_dir_arg",
    default=None,
    help="Target directory to initialize (default: ~/.blackwall).",
)
def init_command(target_dir_arg: Optional[str]) -> None:
    """Scaffold Blackwall configuration directory with default policy and gateway configs."""
    target_dir = (
        Path(target_dir_arg).expanduser().resolve()
        if target_dir_arg
        else Path.home() / ".blackwall"
    )
    target_dir.mkdir(parents=True, exist_ok=True)

    policy_file = target_dir / "policy.yaml"
    if not policy_file.exists():
        policy_file.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")

    gateway_file = target_dir / "gateway.yaml"
    if not gateway_file.exists():
        gateway_file.write_text(DEFAULT_GATEWAY_YAML, encoding="utf-8")

    db_file = target_dir / "threat_signatures.db"
    if not db_file.exists():
        import sqlite3

        conn = sqlite3.connect(str(db_file))
        conn.close()
        repo = SQLiteThreatRepository(db_path=str(db_file))
        if hasattr(repo, "close"):
            close_fn = getattr(repo, "close")
            if callable(close_fn):
                res = close_fn()
                if inspect.isawaitable(res):
                    asyncio.run(res)

    console.print(f"[bold green]Initialized Blackwall configuration in {target_dir}[/bold green]")


@cli.command(name="stop")
@click.option(
    "--pidfile",
    default=None,
    help="Path to PID file (default: ~/.blackwall/blackwall.pid).",
)
def stop_command(pidfile: Optional[str]) -> None:
    """Stop running Blackwall daemon."""
    pid_path = (
        Path(pidfile).expanduser().resolve()
        if pidfile
        else Path.home() / ".blackwall" / "blackwall.pid"
    )
    pid = read_pid_file(pid_path)
    if pid is None or not is_process_alive(pid):
        remove_pid_file(pid_path)
        console.print("[yellow]Blackwall daemon is not running.[/yellow]")
        return

    if not is_blackwall_process(pid):
        remove_pid_file(pid_path)
        logger.warning(
            "Stale PID file '%s' detected (PID %d is alive but is not a Blackwall process). Removing PID file.",
            pid_path,
            pid,
        )
        console.print(
            f"[yellow]Blackwall daemon is not running (stale PID file for unrelated process PID {pid} cleaned up).[/yellow]"
        )
        return

    stopped = stop_daemon(pid_path)
    if stopped:
        console.print(
            f"[bold green]Blackwall daemon (PID {pid}) stopped successfully.[/bold green]"
        )
    else:
        raise click.ClickException(f"Failed to stop Blackwall daemon (PID {pid}).")


async def _get_db_status(
    db_path: str,
) -> tuple[Optional[dict[str, Any]], Optional[list[dict[str, Any]]], Optional[str]]:
    """Safely fetch threat graph statistics and audit incidents from SQLite repository."""
    repo = SQLiteThreatRepository(db_path=db_path)
    try:
        await repo.initialize()
        stats = await repo.getStatistics()
        incidents = await repo.getAuditIncidents()
        return stats, incidents, None
    except Exception as exc:
        logger.debug("Failed querying database statistics at %s: %s", db_path, exc)
        return None, None, str(exc)
    finally:
        await _safe_close_repo(repo)


@cli.command(name="status")
@click.option(
    "--pidfile",
    default=None,
    help="Path to PID file (default: ~/.blackwall/blackwall.pid).",
)
@click.option(
    "--db-path",
    default=None,
    help="Path to SQLite threat database.",
)
@click.pass_context
def status_command(
    ctx: click.Context, pidfile: Optional[str], db_path: Optional[str]
) -> None:
    """Check Blackwall daemon liveness and threat database statistics."""
    pid_path = (
        Path(pidfile).expanduser().resolve()
        if pidfile
        else Path.home() / ".blackwall" / "blackwall.pid"
    )
    pid = read_pid_file(pid_path)

    table = Table(
        title="Blackwall MCP Gateway Status",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Property", style="bold white")
    table.add_column("Value", style="yellow")

    if pid and is_process_alive(pid) and is_blackwall_process(pid):
        table.add_row("Daemon State", f"[bold green]Running (PID {pid})[/bold green]")
        table.add_row("PID File", str(pid_path))
    else:
        table.add_row("Daemon State", "[bold red]Stopped[/bold red]")
        table.add_row("PID File", f"{pid_path} (inactive)")

    resolved_db = (
        db_path
        or (ctx.obj.get("db_path") if ctx.obj.get("db_path") != "./blackwall.db" else None)
        or str(Path.home() / ".blackwall" / "threat_signatures.db")
    )
    if not Path(resolved_db).exists() and Path("./blackwall.db").exists():
        resolved_db = "./blackwall.db"

    table.add_row("Threat DB", resolved_db)
    incidents = None
    if Path(resolved_db).exists():
        try:
            stats, incidents, db_err = asyncio.run(_get_db_status(resolved_db))
            if db_err:
                table.add_row(
                    "DB Accessible",
                    f"[bold red]Inaccessible/Corrupted ({db_err})[/bold red]",
                )
            else:
                table.add_row("DB Accessible", "[green]Yes[/green]")
                if stats is not None:
                    table.add_row("Total Signatures", str(stats.get("totalSignatures", 0)))
                    table.add_row(
                        "Avg Matches / Sig",
                        f"{stats.get('avgMatchesPerSignature', 0.0):.2f}",
                    )
                    table.add_row(
                        "Cache Hit Rate",
                        f"{stats.get('cacheHitRate', 0.0):.1%}",
                    )
                if incidents is not None:
                    table.add_row("Recent Verdicts", f"{len(incidents)} logged")
        except Exception as exc:
            logger.debug("Failed fetching DB statistics: %s", exc)
            table.add_row(
                "DB Accessible",
                f"[bold red]Inaccessible/Corrupted ({exc})[/bold red]",
            )
    else:
        table.add_row("DB Accessible", "[dim]Not initialized[/dim]")

    console.print(table)

    if Path(resolved_db).exists() and incidents:
        incidents_table = Table(
            title="Recent Security Incidents & Verdicts",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        incidents_table.add_column("Incident ID", style="bold cyan")
        incidents_table.add_column("Type", style="yellow")
        incidents_table.add_column("Details")
        for inc in incidents[:5]:
            incidents_table.add_row(
                inc.get("incident_id", "unknown"),
                inc.get("incident_type", "UNKNOWN"),
                str(inc.get("details", ""))[:80],
            )
        console.print(incidents_table)


async def _run_gateway(
    transport: str,
    host: str,
    port: int,
    auth_token: Optional[str],
    upstream_mgr: Optional[UpstreamManager],
    db_path: str,
    policy_path: Optional[str] = None,
) -> None:
    """Internal coroutine to run the MCP gateway server."""
    repo = None
    try:
        if upstream_mgr:
            await upstream_mgr.start()

        downstream_handler = upstream_mgr.handle_request if upstream_mgr else None

        try:
            repo = SQLiteThreatRepository(db_path=db_path)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialize SQLiteThreatRepository at {db_path}: {exc}"
            ) from exc

        # Policy resolution: explicit policy_path or default ~/.blackwall/policy.yaml
        resolved_policy = policy_path
        if not resolved_policy:
            default_policy = Path.home() / ".blackwall" / "policy.yaml"
            if default_policy.exists():
                resolved_policy = str(default_policy)

        policy_server = None
        if resolved_policy:
            pol_path = Path(resolved_policy).expanduser().resolve()
            if not pol_path.exists():
                raise FileNotFoundError(f"Policy file not found: {pol_path}")
            try:
                from blackwall.policy.engine import StructuralGatingEngine
                from blackwall.policy.semantic import SemanticGatingEngine
                from blackwall.policy.server import HybridPolicyServer

                struct_engine = StructuralGatingEngine()
                struct_engine.load_policy(str(pol_path))
                semantic_engine = SemanticGatingEngine(repo=repo)
                policy_server = HybridPolicyServer(
                    structural_engine=struct_engine,
                    semantic_engine=semantic_engine,
                )
                logger.info("Loaded security policy from %s", pol_path)
            except Exception as exc:
                if policy_path:
                    raise RuntimeError(
                        f"Failed to load policy from '{pol_path}': {exc}"
                    ) from exc
                else:
                    logger.warning(
                        "Default policy.yaml exists at %s but failed to load: %s",
                        pol_path,
                        exc,
                    )

        # Resolver initialization - FAIL FAST, never fall back to resolver=None
        try:
            from google import genai

            project = os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
            client = genai.Client(vertexai=True, project=project)
            from blackwall.sync_resolver import SyncResolver

            resolver = SyncResolver(client=client, repo=repo, policy_server=policy_server)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialize SyncResolver: {exc}. "
                "Security evaluation cannot be bypassed."
            ) from exc

        server = MCPGatewayServer(
            host=host,
            port=port,
            auth_token=auth_token,
            resolver=resolver,
            downstream_handler=downstream_handler,
        )

        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _sig_handler() -> None:
            logger.info("Received termination signal, stopping gateway...")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _sig_handler)
            except (NotImplementedError, RuntimeError):
                pass

        if transport.lower() == "http":
            await server.start_http()
            await stop_event.wait()
            await server.stop()
        else:
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            w_transport, w_protocol = await loop.connect_write_pipe(
                asyncio.streams.FlowControlMixin, sys.stdout
            )
            writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
            stdio_task = asyncio.create_task(server.handle_stdio_stream(reader, writer))
            stop_task = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait(
                [stdio_task, stop_task], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
    finally:
        if upstream_mgr:
            await upstream_mgr.stop()
        if repo and hasattr(repo, "close"):
            res = repo.close()
            if inspect.isawaitable(res):
                await res


@cli.command(name="serve")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"], case_sensitive=False),
    default="stdio",
    help="Transport protocol (stdio or http).",
)
@click.option(
    "--port",
    type=int,
    default=9229,
    help="Port for HTTP transport (default: 9229).",
)
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host address for HTTP transport (default: 127.0.0.1).",
)
@click.option(
    "--wrap",
    default=None,
    help="Downstream MCP tool server command to wrap as a stdio child process.",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    help="Path to gateway.yaml multi-server routing configuration.",
)
@click.option(
    "--policy",
    "policy_path",
    default=None,
    help="Path to policy.yaml configuration.",
)
@click.option(
    "--db",
    "--db-path",
    "db_arg",
    default=None,
    help="Path to SQLite threat database.",
)
@click.option(
    "--pidfile",
    default=None,
    help="Path to PID file (default: ~/.blackwall/blackwall.pid).",
)
@click.option(
    "--logfile",
    default=None,
    help="Path to log file (default: ~/.blackwall/blackwall.log).",
)
@click.option(
    "--foreground",
    is_flag=True,
    default=False,
    help="Run gateway in foreground mode.",
)
@click.option(
    "--auth-token",
    default=None,
    help="Pre-shared bearer auth token for HTTP transport (required for non-loopback).",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Logging level.",
)
@click.option(
    "--skip-gcp-check",
    is_flag=True,
    default=False,
    help="Bypass GCP Vertex AI credentials check (for testing and offline eval).",
)
@click.pass_context
def serve_command(
    ctx: click.Context,
    transport: str,
    port: int,
    host: str,
    wrap: Optional[str],
    config_path: Optional[str],
    policy_path: Optional[str],
    db_arg: Optional[str],
    pidfile: Optional[str],
    logfile: Optional[str],
    foreground: bool,
    auth_token: Optional[str],
    log_level: str,
    skip_gcp_check: bool,
) -> None:
    """Start Blackwall MCP Gateway daemon or foreground process."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # 1. Non-loopback auth token startup guard
    resolved_auth = auth_token or os.environ.get("BLACKWALL_AUTH_TOKEN")
    is_loopback = (
        host in ("127.0.0.1", "localhost", "::1", "[::1]")
        or host.startswith("127.")
    )
    if not is_loopback and not resolved_auth:
        raise click.ClickException(
            f"Refusing to start MCP Gateway on non-loopback host '{host}' "
            f"without an auth token. Provide --auth-token or set BLACKWALL_AUTH_TOKEN."
        )

    # 2. GCP Vertex AI credential validation
    if not skip_gcp_check:
        valid_gcp, gcp_err = validate_gcp_credentials()
        if not valid_gcp:
            raise click.ClickException(gcp_err)

    base_dir = Path.home() / ".blackwall"
    pid_path = (
        Path(pidfile).expanduser().resolve()
        if pidfile
        else base_dir / "blackwall.pid"
    )
    log_path = (
        Path(logfile).expanduser().resolve()
        if logfile
        else base_dir / "blackwall.log"
    )
    resolved_db = db_arg or ctx.obj.get("db_path") or str(base_dir / "threat_signatures.db")

    existing_pid = read_pid_file(pid_path)
    if existing_pid and is_process_alive(existing_pid):
        raise click.ClickException(
            f"Blackwall gateway daemon is already running (PID {existing_pid})."
        )

    upstream_mgr: Optional[UpstreamManager] = None
    if wrap:
        upstream_mgr = UpstreamManager(wrap_command=wrap)
    elif config_path:
        upstream_mgr = UpstreamManager(config_path=config_path)
    elif (base_dir / "gateway.yaml").exists():
        try:
            upstream_mgr = UpstreamManager(config_path=str(base_dir / "gateway.yaml"))
        except Exception as exc:
            logger.warning("Default gateway.yaml exists but failed to load: %s", exc)

    if transport.lower() == "stdio":
        # Stdio transport requires an interactive/bidirectional pipe stream attached to
        # the MCP client/parent process and must run in the foreground without daemonization.
        foreground = True

    if not foreground:
        daemonize(pid_path, log_path)
    else:
        if pidfile:
            write_pid_file(pid_path)

    try:
        asyncio.run(
            _run_gateway(
                transport=transport,
                host=host,
                port=port,
                auth_token=resolved_auth,
                upstream_mgr=upstream_mgr,
                db_path=resolved_db,
                policy_path=policy_path,
            )
        )
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(f"Failed to start Blackwall gateway: {exc}") from exc
    finally:
        if foreground and pidfile:
            remove_pid_file(pid_path)


# Entry point aliases
main = cli

if __name__ == "__main__":
    cli()
