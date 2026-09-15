"""TASK-5.1 benchmark workload contracts (Section 57: Realistic Workload Scale).

Guards `scripts/benchmark_rust_hotpaths.py` against regressing to toy inputs:
the IOC + entropy hot path MUST exercise a fixed 1KB threat payload with
realistic IOC variety, per `.agents/rules/testing_and_hygiene.md` Section 57.
"""

import importlib.util
import sys
from pathlib import Path

BENCHMARK_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "benchmark_rust_hotpaths.py"
)


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location(
        "benchmark_rust_hotpaths", BENCHMARK_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_ioc_entropy_payload_meets_1kb_contract():
    """Section 57: IOC + entropy workload MUST run on a fixed 1KB payload."""
    module = _load_benchmark_module()
    payload = module._build_ioc_payload()
    assert len(payload) >= 1024, (
        f"IOC payload below 1KB benchmark contract: {len(payload)} bytes"
    )


def test_ioc_payload_embeds_realistic_ioc_variety():
    """Payload must exercise extract_iocs with IP, domain, hash, and URL IOCs.

    Asserted as exact whitespace-delimited tokens (stronger than substring
    matching: each marker must survive intact as a standalone indicator).
    """
    module = _load_benchmark_module()
    payload = module._build_ioc_payload()
    expected_tokens = {
        "192.168.1.200",
        "c2.malware.example.com",
        "sha256:deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef",
        "https://evil.example.org/payload.bin",
        "ip=10.0.0.5",
    }
    assert expected_tokens <= set(payload.split())
