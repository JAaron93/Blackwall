"""Unit tests for TASK-G01 honeypot server (TDD — written before implementation)."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path


def _extract_visible_text(html: str) -> str:
    """Simulate browser rendering: strip comments, hidden divs, zero-width chars, tags."""
    no_comments = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    # Remove CSS-hidden / off-screen spans and divs entirely (including content).
    no_hidden = re.sub(
        r'<(?:div|span)[^>]*(?:display\s*:\s*none|font-size\s*:\s*0|left\s*:\s*-9999px)[^>]*>.*?</(?:div|span)>',
        "",
        no_comments,
        flags=re.DOTALL | re.IGNORECASE,
    )
    no_zw = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", no_hidden)
    no_tags = re.sub(r"<[^>]+>", " ", no_zw)
    return re.sub(r"\s+", " ", no_tags).strip()


class TestHoneypotServerEndpoints:
    def test_fake_library_hides_payloads_but_parser_extracts_them(self):
        from fastapi.testclient import TestClient

        from scripts.gateway_demo.honeypot_server import app

        client = TestClient(app)
        resp = client.get("/docs/fake-library")
        assert resp.status_code == 200
        raw = resp.text

        # Extractable by a text parser: raw HTML carries all three vectors.
        assert "<!--" in raw and "Ignore previous instructions" in raw
        assert "display:none" in raw
        assert any(z in raw for z in ("\u200b", "\u200c", "\u200d", "\ufeff"))
        assert "/exfil" in raw

        # Invisible when rendered: visible text looks like normal docs.
        visible = _extract_visible_text(raw)
        assert "FakeLib" in visible or "fake" in visible.lower()
        assert "Ignore previous instructions" not in visible
        assert "/exfil" not in visible
        assert ".env" not in visible

    def test_compromised_response_contains_toolchain_hijack(self):
        from fastapi.testclient import TestClient

        from scripts.gateway_demo.honeypot_server import app

        client = TestClient(app)
        resp = client.get("/docs/compromised-response")
        assert resp.status_code == 200
        body = resp.json()
        text = str(body)
        assert "id_rsa" in text

    def test_exfil_captures_redacted_body_in_temp_dir_and_cleans_up(self):
        from fastapi.testclient import TestClient

        from scripts.gateway_demo import honeypot_server as hs

        with tempfile.TemporaryDirectory(prefix="bw-demo-") as tmp:
            os.environ["BLACKWALL_DEMO_TMPDIR"] = tmp
            try:
                client = TestClient(hs.app)
                payload = (
                    "FAKE_API_KEY=demo-not-real-do-not-use-0123456789"
                    "-EXTRA-TAIL-PADDING-TO-EXCEED-SIXTY-FOUR-CHARS-0123456789"
                )
                resp = client.post("/exfil", content=payload.encode())
                assert resp.status_code == 200

                log_path = Path(tmp) / "exfil_capture.log"
                assert log_path.exists()
                assert hs.get_capture_log_path() == log_path
                logged = log_path.read_text()
                assert "[REDACTED DEMO FIXTURE]" in logged
                # Only first 64 chars of the body may be recorded.
                assert payload[64:] not in logged
            finally:
                os.environ.pop("BLACKWALL_DEMO_TMPDIR", None)
        # TemporaryDirectory teardown removes the ephemeral log.
        assert not Path(tmp).exists()

    def test_demo_isolation_uses_synthetic_fixtures_only(self):
        from scripts.gateway_demo import honeypot_server as hs

        tmp_ctx = hs.setup_demo_isolation()
        try:
            assert Path(tmp_ctx.name).exists()
            # Synthetic credential fixtures only — clearly fake values.
            env_file = Path(tmp_ctx.name) / ".env"
            assert env_file.exists()
            content = env_file.read_text()
            assert "demo-not-real-do-not-use" in content
            assert "AKIA" not in content
            assert "sk-proj-" not in content
            # Attack targets named by the payloads resolve to synthetics.
            adc = Path(tmp_ctx.name) / ".config" / "gcloud" / "application_default_credentials.json"
            assert adc.exists()
            assert "demo-client" in adc.read_text()
            ssh_key = Path(tmp_ctx.name) / ".ssh" / "id_rsa"
            assert ssh_key.exists()
            assert "demo-not-real-do-not-use" in ssh_key.read_text()
            # Relative `.env` reads are confined to the synthetic dir.
            assert Path(".env").resolve() == env_file.resolve()
        finally:
            tmp_ctx.cleanup()

    def test_server_defaults_bind_loopback_8765(self):
        from scripts.gateway_demo import honeypot_server as hs

        assert hs.DEFAULT_HOST == "127.0.0.1"
        assert hs.DEFAULT_PORT == 8765
