# Test and Documentation Hygiene Rules

## 1. Absolute Imports in Test Modules
* **Rule:** In `tests/` subdirectories (e.g., `tests/integration/`, `tests/unit/`), always use absolute imports from the repository root (e.g., `from tests.integration.helpers import ...`) rather than relative imports (`from .helpers import ...`).
* **Rationale:** Pytest collects test files as standalone modules during test discovery. Relative imports in test submodules cause `ImportError: attempted relative import with no known parent package` when running pytest directly without package context.

## 2. Portable Documentation Links
* **Rule:** Markdown documentation files in `docs/` must use **repo-relative markdown paths** (e.g., `[helpers.py](../tests/integration/helpers.py)`), and must **never** hard-code local environment `file:///Users/...` or `file:///C:/...` URLs.
* **Rationale:** Local absolute `file://` URLs break on GitHub/GitLab repository browsers, fail for other contributors, and leak local machine paths.

## 3. Mock Type Signature Alignment
* **Rule:** Test helper functions creating mock objects must ensure the return type annotation matches the actual mock class instantiated (e.g., `AsyncMock` vs `MagicMock`). Async side-effect handlers assigned to mock methods should be wrapped with `AsyncMock(side_effect=_fn)` so callers can inspect call counts and await assertions using `AsyncMock` APIs.
