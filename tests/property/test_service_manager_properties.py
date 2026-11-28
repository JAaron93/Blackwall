"""Property-based checks for the FR-10 non-tilde / secret-isolation invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from blackwall.gateway import service as svc


@settings(max_examples=25, deadline=None)
@given(
    path_suffix=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-/", min_size=1, max_size=40
    ).filter(lambda value: value.strip("/")),
    secret=st.text(
        # Uppercase-only keeps the generated secret disjoint from lowercase
        # temporary paths, avoiding a coincidental substring match.
        alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        min_size=20,
        max_size=48,
    ),
)
def test_plist_never_contains_tilde_or_secret_value(
    path_suffix: str, secret: str
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        adc_dir = Path(tmp) / ".config" / "gcloud"
        adc_dir.mkdir(parents=True)
        (adc_dir / "application_default_credentials.json").write_text("{}")
        config = svc.build_service_config(
            config=f"~/{path_suffix}/gateway.yaml",
            logfile=f"~/{path_suffix}/blackwall.log",
            db=f"~/{path_suffix}/threats.db",
            home=Path(tmp),
            env={
                "GCP_PROJECT": "property-project",
                "PATH": "/usr/bin",
                "TYPESAFE_API_KEY": secret,
            },
        )
        xml = svc.generate_plist(config)
    assert "~" not in xml
    assert secret not in xml
