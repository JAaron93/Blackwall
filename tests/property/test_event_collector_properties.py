"""Property-based tests for EventStreamCollector (Task 4).

Uses Hypothesis to verify properties 1, 2, and 76 across generated inputs.
"""

from datetime import datetime, timezone, timedelta
import uuid

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from blackwall.enterprise.advanced_threat_detection.collector import (
    EventStreamCollector,
)
from blackwall.enterprise.advanced_threat_detection.enums import EventSource
from blackwall.enterprise.advanced_threat_detection.models import NormalizedEvent

# Strategies
non_empty_str_st = st.text(min_size=1).filter(lambda s: bool(s.strip()))
event_source_st = st.sampled_from(EventSource)
metadata_dict_st = st.dictionaries(
    keys=st.text(min_size=1, max_size=10),
    values=st.one_of(st.integers(), st.floats(allow_nan=False), st.text(max_size=20)),
    max_size=5,
)

collector = EventStreamCollector()


# Property 1: Event Normalization Source Mapping
@settings(max_examples=100)
@given(
    source=event_source_st,
    agent_id=non_empty_str_st,
    action=non_empty_str_st,
    target=non_empty_str_st,
    meta=metadata_dict_st,
)
def test_property_1_event_normalization_source_mapping(
    source: EventSource, agent_id: str, action: str, target: str, meta: dict
):
    """Property 1: For any event originating from a specific pillar source,

    the Event_Collector SHALL normalize it with the corresponding EventSource enum value.
    Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
    """
    raw_event = {
        "agent_id": agent_id,
        "action": action,
        "target": target,
        "metadata": meta,
    }
    normalized = collector.normalize_event(source, raw_event)
    assert normalized.source == source


# Property 2: Event Enrichment Completeness
@settings(max_examples=100)
@given(
    source=event_source_st,
    agent_id=non_empty_str_st,
    action=non_empty_str_st,
    target=non_empty_str_st,
    meta=metadata_dict_st,
)
def test_property_2_event_enrichment_completeness(
    source: EventSource, agent_id: str, action: str, target: str, meta: dict
):
    """Property 2: For any event being normalized,

    the Event_Collector SHALL enrich it with both temporal context and agent metadata fields.
    Validates: Requirement 1.6
    """
    raw_event = {
        "agent_id": agent_id,
        "action": action,
        "target": target,
        "metadata": meta,
    }
    normalized = collector.normalize_event(source, raw_event)

    # Temporal context checks
    assert normalized.timestamp is not None
    assert normalized.timestamp.tzinfo is not None
    assert normalized.timestamp.utcoffset() == timedelta(0)
    assert "ingested_at" in normalized.metadata

    # Agent metadata checks
    assert normalized.agent_id == agent_id.strip()
    assert normalized.action == action.strip()
    assert normalized.target == target.strip()


# Property 76: Agent ID Non-Empty Validation
@settings(max_examples=100)
@given(
    empty_agent_id=st.one_of(st.just(""), st.just("   "), st.just("\t\n")),
    source=event_source_st,
    action=non_empty_str_st,
    target=non_empty_str_st,
)
def test_property_76_agent_id_non_empty_validation(
    empty_agent_id: str, source: EventSource, action: str, target: str
):
    """Property 76: For any Normalized_Event, the agent_id SHALL be validated to not be an empty string.

    Validates: Requirement 15.4
    """
    raw_event = {
        "agent_id": empty_agent_id,
        "action": action,
        "target": target,
    }
    with pytest.raises((ValueError, ValidationError)):
        collector.normalize_event(source, raw_event)
