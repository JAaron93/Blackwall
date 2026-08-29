"""Unit tests for Rust-accelerated IOC extraction and Shannon entropy calculation."""

import math
from collections import Counter
from urllib.parse import urlparse
import pytest
from blackwall import _core_rs


def test_entropy_parity_with_python_reference():
    """Verify Shannon entropy matches Python reference implementation across varied test strings."""
    test_cases = [
        "",
        "a",
        "aaaaa",
        "abcdefgh",
        "The quick brown fox jumps over the lazy dog.",
        "eval(base64.b64decode('aW1wb3J0IG9zCnN5c3RlbSgncm0gLXJmIC8nKQ=='))",
        "0123456789ABCDEF0123456789abcdef",
    ]

    for s in test_cases:
        actual = _core_rs.calculate_entropy(s)
        if not s:
            expected = 0.0
        else:
            counts = Counter(s)
            expected = 0.0
            for count in counts.values():
                p = count / len(s)
                expected -= p * math.log2(p)

        assert actual == pytest.approx(expected, rel=1e-5), f"Entropy mismatch for '{s}'"


def test_iocs_extraction_ipv4_and_ipv6():
    """Verify extraction of valid IPv4 and IPv6 addresses with loopbacks and invalid exclusion."""
    strings = [
        "Primary host 192.168.1.100 and public 8.8.8.8",
        "Invalid IP 999.999.999.999 or 10.0.0.999",
        "IPv6 host 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "Compressed IPv6 2001:db8::1, 2001:db8::2/path, 2001:db8::1:2:3:4:5, 2001:db8::, fe80::, and loopback ::1",
        "Adjacent hex 0xdeadbeef::1 and prefix2001:db8::1 should not extract corrupt IPs",
        "Port-bound IPv4 10.0.0.1:8080 should extract IP",
    ]

    iocs = _core_rs.extract_iocs(strings)
    ips = set(iocs.get("ips", []))

    assert "192.168.1.100" in ips
    assert "8.8.8.8" in ips
    assert "10.0.0.1" in ips
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in ips
    assert "2001:db8::1" in ips
    assert "2001:db8::2" in ips
    assert "2001:db8::1:2:3:4:5" in ips
    assert "2001:db8::" in ips
    assert "fe80::" in ips
    assert "::1" in ips
    assert "999.999.999.999" not in ips
    assert "10.0.0.999" not in ips
    assert "0xdeadbeef::1" not in ips
    assert "deadbeef::1" not in ips
    assert "prefix2001:db8::1" not in ips


def test_iocs_extraction_urls_and_domains():
    """Verify extraction of URLs and domains without false positive IP domain extraction."""
    strings = [
        "Download payload from https://evil-domain.com/malware.bin",
        "API endpoint at http://api.threat-intel.org/v1/query?token=xyz",
        "C2 server at c2.botnet-network.xyz:8080",
    ]

    iocs = _core_rs.extract_iocs(strings)
    urls = set(iocs.get("urls", []))
    domains = set(iocs.get("domains", []))
    url_hosts = {parsed.hostname for parsed in (urlparse(u) for u in urls) if parsed.hostname}

    assert "https://evil-domain.com/malware.bin" in urls
    assert "http://api.threat-intel.org/v1/query?token=xyz" in urls
    assert "evil-domain.com" in url_hosts
    assert "c2.botnet-network.xyz" in domains


def test_iocs_extraction_hashes():
    """Verify extraction of MD5, SHA1, and SHA256 hashes."""
    strings = [
        "MD5: 5d41402abc4b2a76b9719d911017c592",
        "SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Not a hash: 1234567890",
    ]

    iocs = _core_rs.extract_iocs(strings)
    hashes = iocs.get("hashes", [])

    assert "5d41402abc4b2a76b9719d911017c592" in hashes
    assert "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" in hashes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes
    assert "1234567890" not in hashes
