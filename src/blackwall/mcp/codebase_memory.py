from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, Field

from blackwall.mcp.transport import MCPTransportError, call_mcp_tool_http
from blackwall.validators import utc_now

if TYPE_CHECKING:
    from blackwall.models import CBMResponse


def _parse_mcp_result(raw: Any) -> Any:
    """Unpacks JSON-RPC 2.0 MCP result payloads if wrapped in content text."""
    if (
        isinstance(raw, dict)
        and "content" in raw
        and isinstance(raw["content"], list)
        and raw["content"]
    ):
        item = raw["content"][0]
        if isinstance(item, dict) and "text" in item:
            try:
                return json.loads(item["text"])
            except (json.JSONDecodeError, TypeError):
                pass
    return raw


# Pydantic models representing the design spec structures
class CriticalSinkType(str, Enum):
    SQL_QUERY = "SQL_QUERY"
    COMMAND_EXEC = "COMMAND_EXEC"
    FILE_WRITE = "FILE_WRITE"
    NETWORK_CALL = "NETWORK_CALL"


class CriticalSink(BaseModel):
    sinkType: CriticalSinkType
    functionName: str
    modulePath: str
    isUnsafe: bool
    mitigationHint: str


class DependencyChain(BaseModel):
    rootFunction: str
    callChain: List[str]
    depth: int
    hasCriticalSink: bool
    criticalSinks: List[str]  # Array of string names of the critical sinks


class DataFlowPath(BaseModel):
    sourceNode: str
    sinkNode: str
    intermediateNodes: List[str]
    isTainted: bool
    sanitizationPoints: List[str]


class BlastRadiusIsolation(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BlastRadiusReport(BaseModel):
    targetNode: str
    affectedModules: List[str]
    affectedFunctions: List[str]
    riskScore: float = Field(..., ge=0.0, le=1.0)
    isolation: BlastRadiusIsolation


class CodebaseMemoryClient:
    """
    Client for interacting with codebase-memory-mcp AST knowledge graph.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        command: Optional[List[str]] = None,
        last_updated: Optional[datetime] = None,
        timeout_seconds: float = 2.0,
        policy: Optional[Any] = None,
    ):
        if not base_url and policy:
            mcp = getattr(policy, "mcpServers", None)
            cbm = getattr(mcp, "codebaseMemory", None) if mcp else None
            base_url = getattr(cbm, "url", None) if cbm else None
        self.base_url = base_url or os.getenv("CBM_MCP_BASE_URL")
        self.command = command
        self.last_updated = last_updated or utc_now()
        self.timeout_seconds = timeout_seconds
        self.mock_data: Dict[str, Any] = {}
        self._init_mocks()

    @classmethod
    def from_policy(cls, policy: Any, **kwargs: Any) -> "CodebaseMemoryClient":
        """Instantiates CodebaseMemoryClient using endpoints configured in policy."""
        return cls(policy=policy, **kwargs)

    def _init_mocks(self) -> None:
        # Predefined mock data for deterministic unit and integration testing
        self.mock_data = {
            "queryDependencyChain": {
                "ProcessOrder": DependencyChain(
                    rootFunction="ProcessOrder",
                    callChain=["ProcessOrder", "ValidatePayment", "ExecuteSQL"],
                    depth=3,
                    hasCriticalSink=True,
                    criticalSinks=["ExecuteSQL"],
                ),
                "safe_func": DependencyChain(
                    rootFunction="safe_func",
                    callChain=["safe_func"],
                    depth=1,
                    hasCriticalSink=False,
                    criticalSinks=[],
                ),
            },
            "identifyCriticalSinks": {
                "ProcessOrder": [
                    CriticalSink(
                        sinkType=CriticalSinkType.SQL_QUERY,
                        functionName="ExecuteSQL",
                        modulePath="src/db/connection.py",
                        isUnsafe=True,
                        mitigationHint="Use parameterized queries instead of string formatting.",
                    )
                ],
                "safe_func": [],
            },
            "traceDataFlow": {
                ("user_input", "ExecuteSQL"): DataFlowPath(
                    sourceNode="user_input",
                    sinkNode="ExecuteSQL",
                    intermediateNodes=["ValidatePayment"],
                    isTainted=True,
                    sanitizationPoints=[],
                ),
                ("safe_input", "safe_sink"): DataFlowPath(
                    sourceNode="safe_input",
                    sinkNode="safe_sink",
                    intermediateNodes=[],
                    isTainted=False,
                    sanitizationPoints=["sanitize_input"],
                ),
            },
            "getBlastRadius": {
                "ProcessOrder": BlastRadiusReport(
                    targetNode="ProcessOrder",
                    affectedModules=["src/db", "src/api"],
                    affectedFunctions=["ProcessOrder", "ValidatePayment", "Checkout"],
                    riskScore=0.75,
                    isolation=BlastRadiusIsolation.MEDIUM,
                ),
                "safe_func": BlastRadiusReport(
                    targetNode="safe_func",
                    affectedModules=["src/utils"],
                    affectedFunctions=["safe_func"],
                    riskScore=0.1,
                    isolation=BlastRadiusIsolation.HIGH,
                ),
            },
        }

    def set_mock_data(self, category: str, key: Any, value: Any) -> None:
        """
        Helper to override mock data for tests.
        """
        if category in self.mock_data:
            self.mock_data[category][key] = value

    def is_graph_stale(self) -> bool:
        """
        Returns true if the AST graph was updated more than 1 hour ago.
        """
        now = utc_now()
        diff = (now - self.last_updated).total_seconds()
        return diff > 3600

    def get_threat_score_penalty(self) -> float:
        """
        Apply threat score penalty of 0.4 when graph is stale (last updated > 1 hour ago)
        """
        return 0.4 if self.is_graph_stale() else 0.0

    async def _execute_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Low-level executor. In production, this communicates with the MCP server
        using HTTP JSON-RPC 2.0 (tools/call). In the absence of live servers or configuration,
        it raises or uses mock data.
        """
        # If no real transport is configured, raise or return mock indicators
        if not self.base_url and not self.command:
            raise NotImplementedError(
                "Real MCP transport not configured. Mocking required."
            )

        if self.base_url:
            return await call_mcp_tool_http(
                endpoint_url=self.base_url,
                tool_name=tool_name,
                arguments=arguments,
                timeout=self.timeout_seconds,
            )

        # Subprocess command transport (future extension)
        raise ConnectionError("Subprocess MCP server transport is not configured.")

    async def _safe_execute(self, coro, fallback: Any) -> Any:
        """
        Executes a coroutine with a 2-second timeout and handles graceful degradation.
        """
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout_seconds)
        except (
            asyncio.TimeoutError,
            ConnectionError,
            NotImplementedError,
            OSError,
            MCPTransportError,
        ):
            # Graceful degradation: return the fallback when CBM is unavailable
            return fallback

    async def queryDependencyChain(self, functionName: str) -> DependencyChain:
        """
        Queries codebase dependency chain returning call chain, depth, and critical sinks.
        """

        async def _query():
            if not self.base_url and not self.command:
                # Mock path
                return self.mock_data["queryDependencyChain"].get(
                    functionName,
                    DependencyChain(
                        rootFunction=functionName,
                        callChain=[functionName],
                        depth=1,
                        hasCriticalSink=False,
                        criticalSinks=[],
                    ),
                )
            # Real path (might fail, triggers fallback)
            res = await self._execute_mcp_tool(
                "trace_path", {"qualified_name": functionName}
            )
            parsed = _parse_mcp_result(res)
            if isinstance(parsed, DependencyChain):
                return parsed
            if isinstance(parsed, dict):
                if (
                    "data" in parsed
                    and isinstance(parsed["data"], dict)
                    and "rootFunction" in parsed["data"]
                ):
                    parsed = parsed["data"]
                if "rootFunction" in parsed:
                    return DependencyChain.model_validate(parsed)
                call_chain = (
                    parsed.get("call_chain")
                    or parsed.get("callChain")
                    or [functionName]
                )
                critical_sinks = (
                    parsed.get("critical_sinks") or parsed.get("criticalSinks") or []
                )
                return DependencyChain(
                    rootFunction=parsed.get("root_function")
                    or parsed.get("rootFunction")
                    or functionName,
                    callChain=list(call_chain),
                    depth=int(parsed.get("depth", len(call_chain))),
                    hasCriticalSink=bool(
                        parsed.get(
                            "has_critical_sink",
                            parsed.get("hasCriticalSink", bool(critical_sinks)),
                        )
                    ),
                    criticalSinks=list(critical_sinks),
                )
            return fallback

        # Graceful fallback: Default to safe/empty DependencyChain
        fallback = DependencyChain(
            rootFunction=functionName,
            callChain=[functionName],
            depth=1,
            hasCriticalSink=False,
            criticalSinks=[],
        )
        return await self._safe_execute(_query(), fallback)

    async def identifyCriticalSinks(self, moduleName: str) -> List[CriticalSink]:
        """
        Detects: SQL_QUERY, COMMAND_EXEC, FILE_WRITE, NETWORK_CALL
        Identifies unsafe sinks accepting unsanitized input.
        """
        # Validate moduleName against injection characters (quotes, semicolons, brackets, etc.)
        if not moduleName or re.search(r"['\"`\x00-\x1f;{}\\]", moduleName):
            return []

        async def _query():
            if not self.base_url and not self.command:
                return self.mock_data["identifyCriticalSinks"].get(moduleName, [])
            res = await self._execute_mcp_tool(
                "query_graph",
                {
                    "query": "MATCH (m:Module {name: $module_name}) RETURN m",
                    "params": {"module_name": moduleName},
                },
            )
            parsed = _parse_mcp_result(res)
            if isinstance(parsed, list):
                sinks = []
                for s in parsed:
                    if isinstance(s, CriticalSink):
                        sinks.append(s)
                    elif isinstance(s, dict):
                        sinks.append(CriticalSink.model_validate(s))
                return sinks
            if isinstance(parsed, dict):
                sinks_raw = (
                    parsed.get("sinks")
                    or parsed.get("criticalSinks")
                    or parsed.get("data")
                    or []
                )
                if isinstance(sinks_raw, list):
                    return [
                        s
                        if isinstance(s, CriticalSink)
                        else CriticalSink.model_validate(s)
                        for s in sinks_raw
                        if isinstance(s, (dict, CriticalSink))
                    ]
            return []

        return await self._safe_execute(_query(), [])

    async def traceDataFlow(self, variableName: str, context: str) -> DataFlowPath:
        """
        Traces data flow from variable to sink.
        """

        async def _query():
            if not self.base_url and not self.command:
                return self.mock_data["traceDataFlow"].get(
                    (variableName, context),
                    DataFlowPath(
                        sourceNode=variableName,
                        sinkNode=context,
                        intermediateNodes=[],
                        isTainted=False,
                        sanitizationPoints=[],
                    ),
                )
            res = await self._execute_mcp_tool(
                "trace_path", {"variable": variableName, "context": context}
            )
            parsed = _parse_mcp_result(res)
            if isinstance(parsed, DataFlowPath):
                return parsed
            if isinstance(parsed, dict):
                if (
                    "data" in parsed
                    and isinstance(parsed["data"], dict)
                    and "sourceNode" in parsed["data"]
                ):
                    parsed = parsed["data"]
                if "sourceNode" in parsed:
                    return DataFlowPath.model_validate(parsed)
                return DataFlowPath(
                    sourceNode=parsed.get(
                        "source_node", parsed.get("sourceNode", variableName)
                    ),
                    sinkNode=parsed.get("sink_node", parsed.get("sinkNode", context)),
                    intermediateNodes=list(
                        parsed.get(
                            "intermediate_nodes", parsed.get("intermediateNodes", [])
                        )
                    ),
                    isTainted=bool(
                        parsed.get("is_tainted", parsed.get("isTainted", False))
                    ),
                    sanitizationPoints=list(
                        parsed.get(
                            "sanitization_points", parsed.get("sanitizationPoints", [])
                        )
                    ),
                )
            return fallback

        fallback = DataFlowPath(
            sourceNode=variableName,
            sinkNode=context,
            intermediateNodes=[],
            isTainted=False,
            sanitizationPoints=[],
        )
        return await self._safe_execute(_query(), fallback)

    async def getBlastRadius(self, targetNode: str) -> BlastRadiusReport:
        """
        Calculates blast radius including affected modules, risk score, and isolation level.
        """

        async def _query():
            if not self.base_url and not self.command:
                return self.mock_data["getBlastRadius"].get(
                    targetNode,
                    BlastRadiusReport(
                        targetNode=targetNode,
                        affectedModules=[targetNode],
                        affectedFunctions=[targetNode],
                        riskScore=0.0,
                        isolation=BlastRadiusIsolation.HIGH,
                    ),
                )
            res = await self._execute_mcp_tool("get_architecture", {"node": targetNode})
            parsed = _parse_mcp_result(res)
            if isinstance(parsed, BlastRadiusReport):
                return parsed
            if isinstance(parsed, dict):
                if (
                    "data" in parsed
                    and isinstance(parsed["data"], dict)
                    and "targetNode" in parsed["data"]
                ):
                    parsed = parsed["data"]
                if "targetNode" in parsed:
                    return BlastRadiusReport.model_validate(parsed)
                return BlastRadiusReport(
                    targetNode=parsed.get(
                        "target_node", parsed.get("targetNode", targetNode)
                    ),
                    affectedModules=list(
                        parsed.get(
                            "affected_modules",
                            parsed.get("affectedModules", [targetNode]),
                        )
                    ),
                    affectedFunctions=list(
                        parsed.get(
                            "affected_functions",
                            parsed.get("affectedFunctions", [targetNode]),
                        )
                    ),
                    riskScore=float(
                        parsed.get("risk_score", parsed.get("riskScore", 0.0))
                    ),
                    isolation=BlastRadiusIsolation(parsed.get("isolation", "HIGH")),
                )
            return fallback

        fallback = BlastRadiusReport(
            targetNode=targetNode,
            affectedModules=[targetNode],
            affectedFunctions=[targetNode],
            riskScore=0.0,
            isolation=BlastRadiusIsolation.HIGH,
        )
        return await self._safe_execute(_query(), fallback)

    def identifyUnsafeSinks(self, sinks: List[CriticalSink]) -> List[CriticalSink]:
        """
        Filters and returns the list of critical sinks that are flagged as unsafe (accepting unsanitized input).
        """
        return [sink for sink in sinks if sink.isUnsafe]

    def get_mitigation_hint(self, sink_type: CriticalSinkType) -> str:
        """
        Provides mitigation hints based on AST analysis for vulnerability types.
        """
        hints = {
            CriticalSinkType.SQL_QUERY: "Use parameterized queries or ORMs instead of raw string formatting/concatenation.",
            CriticalSinkType.COMMAND_EXEC: "Avoid running shell commands using raw user input. Use subprocess with pre-split argument list and shell=False.",
            CriticalSinkType.FILE_WRITE: "Validate the output file path using os.path.abspath and ensure it resides within the allowed workspace directory to prevent directory traversal.",
            CriticalSinkType.NETWORK_CALL: "Validate and whitelist the target IP/domain before initiating the connection. Restrict to authorized internal endpoints.",
        }
        return hints.get(
            sink_type, "No specific mitigation hint available for this sink type."
        )

    async def query(self, context: Any) -> "CBMResponse":
        """
        Adapter called by SyncResolver._query_cbm(). Accepts a ToolCallContext,
        queries the dependency chain for the tool function, identifies critical
        sinks, and returns a CBMResponse.
        """
        from blackwall.models import CBMResponse, SinkType

        # Extract function name — prefer tool_name from context
        func_name = getattr(context, "tool_name", None) or str(context)

        # Query dependency chain
        dep_chain = await self.queryDependencyChain(func_name)

        # Identify critical sinks on the dependency chain root
        raw_sinks = await self.identifyCriticalSinks(func_name)
        unsafe_sinks = self.identifyUnsafeSinks(raw_sinks)

        # Map CriticalSink → SinkType for CBMResponse
        sink_types: List[SinkType] = []
        for sink in unsafe_sinks:
            try:
                sink_types.append(SinkType(sink.sinkType.value))
            except (ValueError, AttributeError):
                pass

        # blast_radius: use depth as a proxy (1–10 scale)
        blast_radius = float(min(dep_chain.depth * 2, 10))

        return CBMResponse(
            blast_radius=blast_radius,
            critical_sinks=sink_types,
        )
