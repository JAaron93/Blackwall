import pytest
import os
import subprocess
from blackwall.logging import setup_logging

def test_audit_hook_blocks_execution():
    # Setup logging to register the audit hook
    setup_logging()

    # Verify that subprocess calls are blocked with PermissionError
    with pytest.raises(PermissionError, match="Operation not permitted"):
        subprocess.Popen(["echo", "hello"])

    # Verify that os.system calls are blocked with PermissionError
    with pytest.raises(PermissionError, match="Operation not permitted"):
        os.system("echo hello")
