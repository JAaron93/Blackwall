"""Unit tests for certifi cached SSLContext factory."""

import ssl
from blackwall.mcp.transport import get_certifi_ssl_context


def test_get_certifi_ssl_context_returns_ssl_context():
    """Verify get_certifi_ssl_context returns a valid ssl.SSLContext configured with certifi."""
    ctx = get_certifi_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_get_certifi_ssl_context_caches_singleton():
    """Verify successive calls return the exact same cached SSLContext instance."""
    ctx1 = get_certifi_ssl_context()
    ctx2 = get_certifi_ssl_context()
    assert ctx1 is ctx2
