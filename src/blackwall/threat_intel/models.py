"""Threat Intelligence data models and provider protocols."""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class ThreatIndicatorType(str, Enum):
    """Normalized indicator categories supported by threat intelligence providers."""

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"


class ThreatIntelResponse(BaseModel):
    """Standardized threat intelligence response model across all providers."""

    indicator: str
    indicator_type: ThreatIndicatorType
    is_malicious: bool
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_count: int = 0
    total_engines: int = 0
    threat_categories: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    pulse_count: int = 0
    references: list[str] = Field(default_factory=list)
    provider_name: str
    cached: bool = False
    error: str | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict, exclude=True)


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Protocol for all threat intelligence provider implementations."""

    name: str
    supported_indicators: set[ThreatIndicatorType]

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse:
        """Query threat intelligence for a given indicator."""
        ...

    async def is_healthy(self) -> bool:
        """Check provider connectivity and health."""
        ...

    def get_remaining_budget(self) -> int:
        """Return available token bucket or request quota balance."""
        ...
