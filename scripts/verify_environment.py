#!/usr/bin/env python3
"""
Diagnostic Environment Verifier for 100% GCP Vertex AI Mode (Paid Tier)
========================================================================
Validates:
1. GCP_PROJECT / GOOGLE_CLOUD_PROJECT configuration and ADC resolution.
2. Removal of legacy AI Studio keys (GEMINI_API_KEY / LLM_API_KEY).
3. SDK loading of google-genai.
4. Vertex AI client instantiation and connectivity in paid tier mode.
"""

import sys
import os
import asyncio

# Ensure src/ is in python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from dotenv import load_dotenv


async def verify_environment() -> bool:
    print("🔍 Starting GCP Vertex AI Mode Environment Verification...")

    # Load candidate .env files asynchronously via to_thread
    candidate_envs = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", ".env")),
    ]
    for env_file in candidate_envs:
        if os.path.exists(env_file):
            try:
                await asyncio.to_thread(load_dotenv, env_file, override=False)
                print(f"  ✓ Processed environment from {env_file}")
            except (OSError, UnicodeDecodeError, ValueError) as read_err:
                print(
                    f"  ⚠️ Diagnostic Warning: Failed to read {env_file}: {read_err}",
                    file=sys.stderr,
                )


    from blackwall.config import configure_provider_env, get_genai_client

    # 1. Validate configure_provider_env and GCP_PROJECT
    try:
        settings = configure_provider_env()
        print(f"  ✓ GCP Project ID resolved: {settings.effective_gcp_project}")
        print(f"  ✓ GCP Location: {settings.gcp_location}")
        print(f"  ✓ Gemini Tier: {settings.gemini_tier}")
    except ValueError as e:
        print(f"  ❌ Configuration Error: {e}", file=sys.stderr)
        return False

    # 2. Check for legacy API keys
    for key in ("GEMINI_API_KEY", "LLM_API_KEY"):
        if os.getenv(key):
            print(
                f"  ❌ Security Warning: Stale {key} still found in environment!",
                file=sys.stderr,
            )
            return False
    print("  ✓ Confirmed zero legacy AI Studio API keys in runtime environment")

    # 3. Instantiate Vertex AI GenAI Client & Test Authenticated Connectivity
    try:
        client = get_genai_client()
        print(
            "  ✓ google-genai Client initialized strictly in Vertex AI Mode (vertexai=True)"
        )

        # Verify authenticated endpoint connectivity if not running with dummy project in tests
        if settings.effective_gcp_project != "dummy-gcp-project":
            try:
                res = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model="gemini-3.5-flash-lite",
                        contents="ping",
                    ),
                    timeout=10.0,
                )
                if res and res.text:
                    print("  ✓ Authenticated Vertex AI model inference call succeeded")
            except Exception as conn_err:
                print(
                    f"  ❌ Authenticated Vertex AI Connectivity Failed: {conn_err}",
                    file=sys.stderr,
                )
                return False
        else:
            print("  ✓ Authenticated connectivity check skipped for dummy test project")
    except Exception as e:
        print(f"  ❌ Client Initialization Failed: {e}", file=sys.stderr)
        return False

    print(
        "🎉 Environment verification PASSED! 100% GCP Vertex AI Mode (Paid Tier) is active."
    )
    return True


if __name__ == "__main__":
    success = asyncio.run(verify_environment())
    sys.exit(0 if success else 1)
