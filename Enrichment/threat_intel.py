"""
Threat Intelligence Enricher Module
Re-exports backend.Enrichment.threat_intel for root imports.
"""

from backend.Enrichment.threat_intel import ThreatIntelEnricher

__all__ = ["ThreatIntelEnricher"]
