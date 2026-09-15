"""
blackwall.attribution — Attacker Identification & Reporting subsystem.

Exposes:
  - AttackerIdentityExtractor  (extractor.py)
  - IncidentReportGenerator    (reporter.py)
  - SwarmContextProvider & SQLiteSwarmContextProvider (provider.py)
"""

from blackwall.attribution.extractor import AttackerIdentityExtractor
from blackwall.attribution.provider import (
    SQLiteSwarmContextProvider,
    SwarmContextProvider,
)
from blackwall.attribution.reporter import IncidentReportGenerator

__all__ = [
    "AttackerIdentityExtractor",
    "IncidentReportGenerator",
    "SwarmContextProvider",
    "SQLiteSwarmContextProvider",
]
