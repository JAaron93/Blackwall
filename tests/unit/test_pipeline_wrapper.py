"""
Unit tests for Application Pipeline Interception Wrappers (TASK-P01).
Tests ASTPipelineFilter, PipelineSandboxManager, and @guard_pipeline decorator.
"""

import pytest
import asyncio
from blackwall.enterprise.pipeline import (
    ASTPipelineFilter,
    PipelineSandboxManager,
    guard_pipeline,
)


@pytest.fixture
def ast_filter():
    return ASTPipelineFilter()


@pytest.fixture
def sandbox_manager():
    return PipelineSandboxManager()


def test_ast_filter_detects_unsafe_pickle(ast_filter):
    unsafe_code = "import pickle\ndata = pickle.loads(untrusted_bytes)"
    res = ast_filter.inspect_code(unsafe_code)
    assert res["is_safe"] is False
    assert "pickle.loads" in res["violations"]


def test_ast_filter_detects_unsafe_os_exec(ast_filter):
    unsafe_code = "import os\nos.system('rm -rf /tmp/test')"
    res = ast_filter.inspect_code(unsafe_code)
    assert res["is_safe"] is False
    assert "os.system" in res["violations"]


def test_ast_filter_detects_ssti_injection(ast_filter):
    unsafe_template = "{{ ''.__class__.__mro__[2].__subclasses__() }}"
    res = ast_filter.inspect_code(unsafe_template)
    assert res["is_safe"] is False
    assert "ssti_injection" in res["violations"]


def test_ast_filter_allows_benign_code(ast_filter):
    benign_code = "def parse_data(items):\n    return [item.upper() for item in items]"
    res = ast_filter.inspect_code(benign_code)
    assert res["is_safe"] is True
    assert len(res["violations"]) == 0


@pytest.mark.asyncio
async def test_pipeline_sandbox_manager_execute_guarded(sandbox_manager):
    def loader_routine(data_path):
        return f"loaded:{data_path}"

    result = await sandbox_manager.execute_guarded(loader_routine, "/tmp/dataset.csv")
    assert result["contained"] is True
    assert "sandbox_id" in result
    assert result["status"] == "EXECUTED"


@pytest.mark.asyncio
async def test_guard_pipeline_decorator():
    @guard_pipeline(sandbox_type="gvisor")
    async def process_dataset(source_url: str):
        return f"processed:{source_url}"

    res = await process_dataset("https://example.com/data.parquet")
    assert res["contained"] is True
    assert res["status"] == "EXECUTED"
