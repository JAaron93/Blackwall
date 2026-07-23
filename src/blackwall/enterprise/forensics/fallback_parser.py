"""
Standalone Lightweight Fallback Parser (`blackwall.enterprise.forensics.fallback_parser`).
Provides regex & AST heuristic threat signature extraction when Ollama/GPU is offline.
Guarantees 100% availability with zero network or external daemon requirements.
"""

import ast
import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class LightweightForensicParser:
    """Regex & AST heuristic forensic log analyzer active when Ollama/GPU is offline."""

    # High-confidence threat regex patterns
    PATTERNS = [
        (
            r"(/bin/(bash|sh|zsh)\s+-i|\/dev\/tcp\/|pty\.spawn|nc\s+-e)",
            "CRITICAL",
            "reverse_shell",
            "Reverse shell execution attempt detected",
        ),
        (
            r"(pickle\.loads|yaml\.unsafe_load|eval\(base64)",
            "CRITICAL",
            "unsafe_deserialization",
            "Unsafe deserialization / code injection attempt detected",
        ),
        (
            r"(\/\.aws\/credentials|\/\.ssh\/id_rsa|\/etc\/shadow|\/etc\/passwd)",
            "HIGH",
            "credential_access",
            "Unauthorized access attempt to sensitive system/cloud credentials",
        ),
        (
            r"(\.\.\/\.\.\/|\.\.\\\.\.\\)",
            "HIGH",
            "directory_traversal",
            "Path traversal sequence detected in file access request",
        ),
        (
            r"(subprocess\.Popen\(.*shell=True|os\.system\(.*nc|sh\s+-c)",
            "HIGH",
            "command_injection",
            "Command execution primitive detected in process call",
        ),
    ]

    def parse(self, log_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse log event dictionary using regex and AST heuristics.
        Returns structured triage report dict.
        """
        raw_str = str(log_payload)
        matched_categories: List[str] = []
        max_severity = "LOW"
        matched_patterns: List[str] = []
        descriptions: List[str] = []

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        for regex_pattern, severity, category, desc in self.PATTERNS:
            match = re.search(regex_pattern, raw_str, re.IGNORECASE)
            if match:
                matched_categories.append(category)
                matched_patterns.append(match.group(0))
                descriptions.append(desc)
                if severity_rank[severity] > severity_rank[max_severity]:
                    max_severity = severity

        # AST inspection on string content if command / python code provided
        for field_name in ("command", "code", "script", "payload"):
            cmd_code = log_payload.get(field_name)
            if isinstance(cmd_code, str):
                try:
                    tree = ast.parse(cmd_code)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            func_name = ""
                            if isinstance(node.func, ast.Name):
                                func_name = node.func.id
                            elif isinstance(node.func, ast.Attribute):
                                func_name = node.func.attr
                            if func_name.lower() in ("eval", "exec", "system", "popen", "spawn", "loads", "call", "run"):
                                if "command_injection" not in matched_categories:
                                    matched_categories.append("command_injection")
                                    matched_patterns.append(f"ast:{func_name}")
                                    descriptions.append(f"AST heuristic identified unsafe call to '{func_name}'")
                                    if severity_rank["HIGH"] > severity_rank[max_severity]:
                                        max_severity = "HIGH"
                except Exception:
                    pass  # Not valid Python code, skip AST check

        is_threat = len(matched_categories) > 0

        return {
            "is_threat": is_threat,
            "threat_level": max_severity if is_threat else "LOW",
            "mode": "standalone_fallback",
            "categories": matched_categories,
            "extracted_pattern": ", ".join(matched_patterns),
            "description": "; ".join(descriptions) if is_threat else "No known threat patterns detected",
        }
