"""Test helper: read a Tier-2 arbiter prompt the way a boundary-respecting model would.

Governing spec: .kiro/specs/tier-1-jev-addition/ (FR-03; ADR 0009 Open Item 3).

``GeminiTier2Backend`` wraps the untrusted tool name, arguments and metadata in
``<tool_call nonce="...">`` and XML-escapes them. ``read_arbiter_prompt`` takes the
prompt apart under the same contract and raises ``BoundaryBroken`` if anything the
caller controls has altered the structure: a second boundary, text outside it, an
unescaped angle bracket in the data, or data that no longer round-trips.

``StructureReadingArbiter`` is a fake Vertex client built on that reader. It
answers BLOCK while the boundary holds and ALLOW once it is broken, so a test
that sees BLOCK has shown the boundary survived the payload. That is a claim
about the prompt's structure. It says nothing about how the live model weighs
text inside an intact boundary; only the live measurement (TASK-F02) can.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import SimpleNamespace
from xml.sax.saxutils import unescape

from blackwall.policy.semantic import Tier2EscalationVerdict

_OPEN = re.compile(r'^<tool_call nonce="(?P<nonce>[0-9a-f]+)">\n', re.MULTILINE)
_REGION = re.compile(
    r"  <tool_name>(?P<tool_name>.*?)</tool_name>\n"
    r"  <arguments>(?P<arguments>.*?)</arguments>\n"
    r"  <metadata>(?P<metadata>.*?)</metadata>",
    re.DOTALL,
)
_ENTITIES = {"&quot;": '"', "&apos;": "'"}
_ARBITER_PREAMBLE = "You are the Tier-2 security arbiter"


class BoundaryBroken(AssertionError):
    """The prompt no longer has the structure the arbiter was told to trust."""


@dataclass(frozen=True)
class ArbiterPromptView:
    nonce: str
    head: str  # everything before the opening tag: the operator's instructions
    tool_name: str  # unescaped
    arguments: str  # unescaped JSON text
    metadata: str  # unescaped JSON text


def read_arbiter_prompt(prompt: str) -> ArbiterPromptView:
    opens = list(_OPEN.finditer(prompt))
    if len(opens) != 1:
        raise BoundaryBroken(
            f"expected one line-anchored opening tag, found {len(opens)}"
        )
    opening = opens[0]
    nonce = opening.group("nonce")
    close = f'\n</tool_call nonce="{nonce}">\n'
    if prompt.count(close) != 1 or not prompt.endswith(close):
        raise BoundaryBroken(
            "the closing tag is missing, repeated, or followed by text"
        )
    region = prompt[opening.end() : len(prompt) - len(close)]
    match = _REGION.fullmatch(region)
    if match is None:
        raise BoundaryBroken(
            "the data region is not exactly tool_name, arguments, metadata"
        )
    fields = {key: match.group(key) for key in ("tool_name", "arguments", "metadata")}
    for key, value in fields.items():
        if "<" in value or ">" in value:
            raise BoundaryBroken(f"unescaped angle bracket in <{key}>")
    return ArbiterPromptView(
        nonce=nonce,
        head=prompt[: opening.start()],
        **{key: unescape(value, _ENTITIES) for key, value in fields.items()},
    )


class StructureReadingArbiter:
    """Fake ``google.genai`` client: BLOCK while the boundary holds, ALLOW once broken."""

    def __init__(self) -> None:
        self.models = self
        self.prompts: list[str] = []
        self.views: list[ArbiterPromptView | None] = []
        self.broken: list[str] = []
        self.other_prompts: list[str] = []

    def generate_content(self, *, model, contents, config):
        if _ARBITER_PREAMBLE not in contents:
            # The resolver shares one Gemini client with background work such as
            # signature synthesis. Those calls are not arbiter prompts.
            self.other_prompts.append(contents)
            return SimpleNamespace(parsed=None, text=None)
        self.prompts.append(contents)
        try:
            self.views.append(read_arbiter_prompt(contents))
            decision = "BLOCK"
        except BoundaryBroken as exc:
            self.views.append(None)
            self.broken.append(str(exc))
            decision = "ALLOW"
        return SimpleNamespace(
            parsed=Tier2EscalationVerdict(
                decision=decision, threat_score=0.9, reasoning="structure reader"
            )
        )
