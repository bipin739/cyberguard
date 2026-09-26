import copy
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
import networkx as nx

from correlation.mitre_mapper import map_event_to_mitre, MITRE_TECHNIQUES


class Campaign:
    """
    Represents a correlated group of security events targeting the same entity
    or executing a multi-stage cyber attack kill chain.
    """
    def __init__(self, campaign_id: str, title: str = ""):
        self.campaign_id = campaign_id
        self.title = title
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.events: List[Dict[str, Any]] = []
        self.entities: Dict[str, Set[str]] = {}
        self.mitre_techniques: List[str] = []
        self.risk_score: float = 0.0
        self.risk_level: Optional[str] = None
        self.response_recommended: Optional[str] = None
        self.explanation: Optional[Dict[str, Any]] = None

    def add_event(self, event: Dict[str, Any]):
        """Adds an event to this campaign and updates entity index."""
        # Ensure event contains campaign_id
        if "entities" not in event:
            event["entities"] = {}
        event["entities"]["campaign_id"] = self.campaign_id

        # Populate mitre_technique if missing
        if not event.get("mitre_technique"):
            event["mitre_technique"] = map_event_to_mitre(event)

        if event.get("mitre_technique") and event["mitre_technique"] not in self.mitre_techniques:
            self.mitre_techniques.append(event["mitre_technique"])

        self.events.append(event)
        self.updated_at = datetime.now(timezone.utc).isoformat()

        # Update entity sets
        for k, v in event.get("entities", {}).items():
            if k == "campaign_id" or v is None:
                continue
            if k not in self.entities:
                self.entities[k] = set()
            self.entities[k].add(str(v))

        # Generate / update title
        self._update_title()

    def _update_title(self):
        targets = []
        if "user_email" in self.entities:
            targets.extend(list(self.entities["user_email"]))
        elif "user_account_id" in self.entities:
            targets.extend(list(self.entities["user_account_id"]))
        
        target_str = targets[0] if targets else "Organization Asset"
        engines = sorted(list(set(e.get("source_engine", "") for e in self.events)))
        self.title = f"Multi-Engine Campaign vs {target_str} ({' + '.join(engines)})"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes campaign to a dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "event_count": len(self.events),
            "events": self.events,
            "entities": {k: sorted(list(v)) for k, v in self.entities.items()},
            "mitre_techniques": [
                {
                    "id": tid,
                    "name": MITRE_TECHNIQUES.get(tid, {}).get("name", tid),
                    "tactic": MITRE_TECHNIQUES.get(tid, {}).get("tactic", "Unknown"),
                    "description": MITRE_TECHNIQUES.get(tid, {}).get("description", "")
                }
                for tid in self.mitre_techniques
            ],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "response_recommended": self.response_recommended,
            "explanation": self.explanation
        }


class CorrelationEngine:
    """
    Maintains the global entity correlation graph and groups events into
    coherent attack campaigns.
    """
    def __init__(self):
        self.graph = nx.Graph()
        self.campaigns: Dict[str, Campaign] = {}
        self.event_index: Dict[str, Dict[str, Any]] = {}
        self._campaign_seq = 1

    def _generate_campaign_id(self) -> str:
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        cid = f"camp_{today_str}-{self._campaign_seq:04d}"
        self._campaign_seq += 1
        return cid

    def _extract_correlatable_entities(self, event: Dict[str, Any]) -> Set[str]:
        """
        Extracts strongly linkable entity tokens from an event.
        Prefixes with entity type to prevent cross-namespace collisions.
        """
        tokens = set()
        entities = event.get("entities", {})

        if entities.get("user_email"):
            tokens.add(f"email:{entities['user_email'].lower().strip()}")

        if entities.get("user_account_id"):
            tokens.add(f"account:{entities['user_account_id'].lower().strip()}")

        if entities.get("ip_address"):
            tokens.add(f"ip:{entities['ip_address'].strip()}")

        if entities.get("domain"):
            tokens.add(f"domain:{entities['domain'].lower().strip()}")

        if entities.get("device_id"):
            tokens.add(f"device:{entities['device_id'].strip()}")

        if entities.get("file_hash_sha256"):
            tokens.add(f"hash:{entities['file_hash_sha256'].lower().strip()}")

        if entities.get("session_id"):
            tokens.add(f"session:{entities['session_id'].strip()}")

        # Also extract linkable values from IOCs
        for ioc in event.get("iocs", []):
            ioc_type = ioc.get("type")
            ioc_val = ioc.get("value")
            if ioc_type and ioc_val:
                tokens.add(f"{ioc_type}:{ioc_val.strip()}")

        return tokens

    def _parse_timestamp(self, ts: Optional[str]) -> Optional[datetime]:
        """Parses ISO 8601 timestamp into a timezone-aware datetime."""
        if not ts:
            return None
        try:
            cleaned = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single incoming event:
        1. Resolves MITRE ATT&CK technique.
        2. Correlates against existing entities / campaigns in the graph
           within a 24-hour temporal window.
        3. Assigns or links to a Campaign.
        4. Returns the enriched event dictionary.
        """
        event_copy = copy.deepcopy(event)
        event_id = event_copy.get("event_id")

        # Map MITRE technique
        if not event_copy.get("mitre_technique"):
            event_copy["mitre_technique"] = map_event_to_mitre(event_copy)

        tokens = self._extract_correlatable_entities(event_copy)
        incoming_dt = self._parse_timestamp(event_copy.get("timestamp"))
        
        # Check if any existing campaign shares any of these tokens within 24 hours
        matched_campaign_id = None
        for cid, campaign in self.campaigns.items():
            for ev in campaign.events:
                ev_tokens = self._extract_correlatable_entities(ev)
                if tokens.intersection(ev_tokens):
                    # Check 24-hour time window
                    ev_dt = self._parse_timestamp(ev.get("timestamp"))
                    if incoming_dt and ev_dt:
                        time_gap_seconds = abs((incoming_dt - ev_dt).total_seconds())
                        if time_gap_seconds <= 24 * 3600:
                            matched_campaign_id = cid
                            break
                    else:
                        # Fallback if timestamp missing or unparseable
                        matched_campaign_id = cid
                        break
            if matched_campaign_id:
                break

        if not matched_campaign_id:
            matched_campaign_id = self._generate_campaign_id()
            self.campaigns[matched_campaign_id] = Campaign(matched_campaign_id)

        campaign = self.campaigns[matched_campaign_id]
        campaign.add_event(event_copy)

        # Update graph representation
        self.graph.add_node(event_id, type="event", data=event_copy)
        for token in tokens:
            self.graph.add_node(token, type="entity")
            self.graph.add_edge(event_id, token)

        self.event_index[event_id] = event_copy
        return event_copy

    def correlate_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Processes and correlates a batch of events sequentially."""
        return [self.process_event(ev) for ev in events]

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Retrieves campaign by ID."""
        return self.campaigns.get(campaign_id)

    def get_all_campaigns(self) -> List[Campaign]:
        """Returns list of all active campaigns sorted by latest update."""
        return sorted(
            list(self.campaigns.values()),
            key=lambda c: c.updated_at,
            reverse=True
        )

    def build_attack_graph(self, campaign_id: str) -> Dict[str, Any]:
        """
        Generates a visual attack graph structure for a specific campaign,
        including nodes (events, entities, kill chain stages) and directed causal edges.
        """
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return {"nodes": [], "edges": []}

        nodes = []
        edges = []
        node_ids = set()

        # Sort campaign events chronologically
        sorted_events = sorted(
            campaign.events,
            key=lambda e: e.get("timestamp", "")
        )

        # 1. Add Event Nodes
        prev_event_id = None
        for idx, ev in enumerate(sorted_events):
            ev_id = ev["event_id"]
            node_ids.add(ev_id)
            mitre_id = ev.get("mitre_technique")
            mitre_info = MITRE_TECHNIQUES.get(mitre_id, {}) if mitre_id else {}

            nodes.append({
                "id": ev_id,
                "label": ev.get("event_type", "Event").replace("_", " ").title(),
                "type": "event",
                "engine": ev.get("source_engine", "unknown"),
                "confidence": ev.get("confidence", 0.0),
                "timestamp": ev.get("timestamp", ""),
                "mitre_technique": mitre_id,
                "mitre_tactic": mitre_info.get("tactic", "Unknown Tactic"),
                "summary": ev.get("evidence", [{}])[0].get("description", "") if ev.get("evidence") else ""
            })

            # Temporal attack progression edge between sequential events
            if prev_event_id:
                edges.append({
                    "id": f"edge_{prev_event_id}_{ev_id}",
                    "source": prev_event_id,
                    "target": ev_id,
                    "label": "Progressed to",
                    "type": "progression"
                })
            prev_event_id = ev_id

            # 2. Add Entity Nodes and connecting edges
            for ent_type, ent_val in ev.get("entities", {}).items():
                if ent_type == "campaign_id" or not ent_val:
                    continue
                ent_node_id = f"ent_{ent_type}_{ent_val}"
                if ent_node_id not in node_ids:
                    node_ids.add(ent_node_id)
                    nodes.append({
                        "id": ent_node_id,
                        "label": f"{ent_type}: {ent_val}",
                        "type": "entity",
                        "entity_type": ent_type,
                        "value": str(ent_val)
                    })

                edges.append({
                    "id": f"edge_{ev_id}_{ent_node_id}",
                    "source": ev_id,
                    "target": ent_node_id,
                    "label": f"Touches {ent_type}",
                    "type": "entity_link"
                })

        return {
            "campaign_id": campaign_id,
            "title": campaign.title,
            "nodes": nodes,
            "edges": edges
        }


# Global singleton instance
correlation_engine = CorrelationEngine()
