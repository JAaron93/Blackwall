from __future__ import annotations

import pytest
from pydantic import ValidationError

from blackwall.threat_intel.models import (
    ThreatIndicatorType,
    ThreatIntelProvider,
    ThreatIntelResponse,
)


def test_threat_indicator_types() -> None:
    assert ThreatIndicatorType.IPV4.value == "IPV4"
    assert ThreatIndicatorType.IPV6.value == "IPV6"
    assert ThreatIndicatorType.DOMAIN.value == "DOMAIN"
    assert ThreatIndicatorType.URL.value == "URL"
    assert ThreatIndicatorType.FILE_HASH.value == "FILE_HASH"


def test_threat_intel_response_defaults() -> None:
    resp = ThreatIntelResponse(
        indicator="198.51.100.1",
        indicator_type=ThreatIndicatorType.IPV4,
        is_malicious=False,
        provider_name="otx",
    )
    assert resp.indicator == "198.51.100.1"
    assert resp.indicator_type == ThreatIndicatorType.IPV4
    assert resp.is_malicious is False
    assert resp.risk_score == 0.0
    assert resp.detection_count == 0
    assert resp.total_engines == 0
    assert resp.threat_categories == []
    assert resp.malware_families == []
    assert resp.pulse_count == 0
    assert resp.references == []
    assert resp.provider_name == "otx"
    assert resp.cached is False


def test_threat_intel_response_malicious_payload() -> None:
    resp = ThreatIntelResponse(
        indicator="malicious-c2.xyz",
        indicator_type=ThreatIndicatorType.DOMAIN,
        is_malicious=True,
        risk_score=0.85,
        detection_count=12,
        total_engines=65,
        threat_categories=["c2", "trojan"],
        malware_families=["Cobalt Strike", "Lumma"],
        pulse_count=4,
        references=["https://otx.alienvault.com/pulse/123"],
        provider_name="otx",
        cached=True,
        raw_response={"raw": "data"},
    )
    assert resp.is_malicious is True
    assert resp.risk_score == 0.85
    assert resp.pulse_count == 4
    assert "Cobalt Strike" in resp.malware_families
    assert resp.cached is True

    # Test serialization excludes raw_response
    dump = resp.model_dump()
    assert "raw_response" not in dump or dump.get("raw_response") == {}


def test_threat_intel_response_risk_score_bounds() -> None:
    with pytest.raises(ValidationError):
        ThreatIntelResponse(
            indicator="test.com",
            indicator_type=ThreatIndicatorType.DOMAIN,
            is_malicious=False,
            risk_score=1.5,  # must be <= 1.0
            provider_name="otx",
        )

    with pytest.raises(ValidationError):
        ThreatIntelResponse(
            indicator="test.com",
            indicator_type=ThreatIndicatorType.DOMAIN,
            is_malicious=False,
            risk_score=-0.1,  # must be >= 0.0
            provider_name="otx",
        )


class DummyProvider:
    name: str = "dummy"
    supported_indicators: set[ThreatIndicatorType] = {ThreatIndicatorType.IPV4}

    async def lookup(
        self, indicator: str, indicator_type: ThreatIndicatorType, timeout: float = 3.0
    ) -> ThreatIntelResponse:
        return ThreatIntelResponse(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=False,
            provider_name=self.name,
        )

    async def is_healthy(self) -> bool:
        return True

    def get_remaining_budget(self) -> int:
        return 10000


def test_threat_intel_provider_protocol() -> None:
    provider: ThreatIntelProvider = DummyProvider()
    assert provider.name == "dummy"
    assert ThreatIndicatorType.IPV4 in provider.supported_indicators
    assert provider.get_remaining_budget() == 10000
