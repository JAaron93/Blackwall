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
from typing import Any, Dict, Optional

import click
from rich import box
from rich.console import Console
from rich.table import Table

from blackwall.db.repository import SQLiteThreatRepository
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


# Entry point aliases
main = cli

if __name__ == "__main__":
    cli()
