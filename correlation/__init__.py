# CyberGuard Correlation Engine Package
from correlation.correlator import correlation_engine, CorrelationEngine, Campaign
from correlation.mitre_mapper import map_event_to_mitre, MITRE_TECHNIQUES

__all__ = [
    "correlation_engine",
    "CorrelationEngine",
    "Campaign",
    "map_event_to_mitre",
    "MITRE_TECHNIQUES"
]
