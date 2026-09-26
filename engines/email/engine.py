import email
from email import policy
from email.parser import BytesParser, Parser
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import urllib.parse

# Known high-value target brands for lookalike detection
TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "bankofamerica",
    "chase", "wellsfargo", "citibank", "dropbox", "docusign", "slack", "zoom",
    "github", "coinbase", "binance", "metamask", "office365", "adobe"
]

# Character visual substitutions (homoglyphs / typosquatting)
HOMOGLYPH_MAP = {
    '1': 'l', 'l': '1', 'i': 'l', '!': 'i',
    '0': 'o', 'o': '0',
    '3': 'e', 'e': '3',
    '4': 'a', '@': 'a',
    '5': 's', '$': 's',
    '8': 'b',
    'v': 'u', 'u': 'v', 'vv': 'w', 'w': 'vv'
}

# Urgency & Social Engineering regex keywords
URGENCY_PATTERNS = [
    (r"\b(immediate(?:ly)?|urgent(?:ly)?|action required|act now|suspended|suspension|locked|terminated?)\b", 0.35, "High urgency or account suspension phrasing"),
    (r"\b(verify(?:ing)? your (?:account|identity|credential|details)|confirm your password|login immediately)\b", 0.40, "Credential verification request"),
    (r"\b(wire transfer|unauthorized payment|invoice overdue|billing statement|crypto transaction|funds release)\b", 0.30, "Financial / payment transfer lure"),
    (r"\b(within 24 hours|within 12 hours|expires today|limited time|last warning|final notice)\b", 0.25, "Artificial time deadline pressure"),
    (r"\b(click here to (?:unlock|restore|verify|claim)|download attachment to view)\b", 0.30, "Coercive call-to-action link directive")
]

URL_EXTRACTOR_REGEX = re.compile(
    r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)",
    re.IGNORECASE
)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_homoglyphs(text: str) -> str:
    """Normalizes known typosquatting homoglyphs to standard ascii characters."""
    normalized = text.lower()
    for k, v in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(k, v)
    return normalized


def check_lookalike_domain(domain: str) -> Optional[Dict[str, Any]]:
    """
    Checks if domain is a typosquatting / lookalike variant of known target brands.
    """
    if not domain:
        return None
    domain_clean = domain.lower().strip()
    # Extract base domain name without TLD
    parts = domain_clean.split(".")
    if len(parts) >= 2:
        base_name = parts[-2]
    else:
        base_name = parts[0]

    normalized_base = _normalize_homoglyphs(base_name)

    for brand in TARGET_BRANDS:
        # Exact match is legitimate (unless subdomain spoofing)
        if base_name == brand:
            continue
        
        # Check normalized equality (e.g., paypa1 -> paypal)
        if normalized_base == brand or brand in normalized_base:
            return {
                "target_brand": brand,
                "reason": f"Domain '{domain}' uses homoglyph/typosquatting spoofing of brand '{brand}'",
                "similarity_score": 0.95
            }
        
        # Check edit distance
        dist = _levenshtein_distance(base_name, brand)
        if 1 <= dist <= 2 and abs(len(base_name) - len(brand)) <= 2:
            return {
                "target_brand": brand,
                "reason": f"Domain '{domain}' has an edit distance of {dist} from legitimate brand '{brand}'",
                "similarity_score": 0.85
            }
    return None


def process(file_path: str) -> Dict[str, Any]:
    """
    Analyzes an email file (.eml, RFC 822 format, or plain text) for phishing,
    social engineering, lookalike domains, and suspicious attachments.
    Emits a fully compliant CyberGuard event.
    """
    raw_bytes = b""
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as exc:
        raw_bytes = b""

    # Parse email using Python standard library
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        try:
            msg = Parser().parsestr(raw_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            msg = None

    sender = ""
    recipient = ""
    subject = ""
    date_header = ""
    body_text = ""
    attachments = []
    headers = {}

    if msg:
        sender = str(msg.get("From", "") or "")
        recipient = str(msg.get("To", "") or "")
        subject = str(msg.get("Subject", "") or "")
        date_header = str(msg.get("Date", "") or "")
        for k, v in msg.items():
            headers[k.lower()] = str(v)
        
        # Extract body text
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition:
                    filename = part.get_filename() or "attachment.dat"
                    attachments.append(filename)
                elif content_type in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += " " + payload.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="ignore")
                else:
                    body_text = msg.get_payload() or ""
            except Exception:
                body_text = ""
    else:
        # Fallback text decoding
        text = raw_bytes.decode("utf-8", errors="ignore")
        body_text = text
        from_match = re.search(r"^From:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        to_match = re.search(r"^To:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        sub_match = re.search(r"^Subject:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if from_match:
            sender = from_match.group(1).strip()
        if to_match:
            recipient = to_match.group(1).strip()
        if sub_match:
            subject = sub_match.group(1).strip()

    # Extract email address and domain from sender and recipient
    sender_email = ""
    sender_domain = ""
    email_match = re.search(r"[\w\.-]+@([\w\.-]+\.\w+)", sender)
    if email_match:
        sender_email = email_match.group(0).lower()
        sender_domain = email_match.group(1).lower()

    recipient_email = ""
    recip_match = re.search(r"[\w\.-]+@([\w\.-]+\.\w+)", recipient)
    if recip_match:
        recipient_email = recip_match.group(0).lower()

    # Extract URLs from body
    all_content = f"{subject}\n{body_text}"
    extracted_urls = list(set(URL_EXTRACTOR_REGEX.findall(all_content)))
    
    # Analysis & Evidence Gathering
    evidence: List[Dict[str, Any]] = []
    iocs: List[Dict[str, Any]] = []
    confidence_signals: List[float] = []

    # 1. Lookalike domain analysis on sender domain
    if sender_domain:
        lookalike = check_lookalike_domain(sender_domain)
        if lookalike:
            evidence.append({
                "description": f"Sender domain '{sender_domain}' is a lookalike/typosquat of legitimate brand '{lookalike['target_brand']}'",
                "field_ref": "domain",
                "weight": 0.50
            })
            iocs.append({
                "type": "domain",
                "value": sender_domain,
                "source": "internal_heuristic"
            })
            confidence_signals.append(0.90)

    # 2. Lookalike domain analysis on extracted URLs
    for url in extracted_urls:
        try:
            parsed = urllib.parse.urlparse(url)
            url_domain = parsed.netloc.lower()
            if ":" in url_domain:
                url_domain = url_domain.split(":")[0]
            
            iocs.append({
                "type": "url",
                "value": url,
                "source": "internal_heuristic"
            })
            
            url_lookalike = check_lookalike_domain(url_domain)
            if url_lookalike:
                evidence.append({
                    "description": f"Embedded URL domain '{url_domain}' mimics target brand '{url_lookalike['target_brand']}'",
                    "field_ref": "url",
                    "weight": 0.45
                })
                confidence_signals.append(0.85)
                iocs.append({
                    "type": "domain",
                    "value": url_domain,
                    "source": "internal_heuristic"
                })
            
            # Check for IP address in URL host (often phishing)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url_domain):
                evidence.append({
                    "description": f"Embedded URL points to raw IP address '{url_domain}' instead of a verified domain name",
                    "field_ref": "url",
                    "weight": 0.40
                })
                confidence_signals.append(0.80)
        except Exception:
            pass

    # 3. Urgency and Social Engineering NLP heuristics
    urgency_hits = 0
    for pattern, weight, label in URGENCY_PATTERNS:
        matches = re.findall(pattern, all_content, re.IGNORECASE)
        if matches:
            urgency_hits += 1
            evidence.append({
                "description": f"Social engineering heuristic detected: {label} (matches: '{matches[0]}')",
                "field_ref": "body_text",
                "weight": weight
            })
            confidence_signals.append(weight * 2.0)

    # 4. Email Auth Header checks (SPF, DKIM, DMARC)
    auth_results = headers.get("authentication-results", "") + headers.get("received-spf", "")
    if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
        evidence.append({
            "description": "SPF (Sender Policy Framework) authentication check failed for sending IP/domain",
            "field_ref": "headers",
            "weight": 0.35
        })
        confidence_signals.append(0.75)
    
    if "dkim=fail" in auth_results.lower():
        evidence.append({
            "description": "DKIM cryptographic signature verification failed",
            "field_ref": "headers",
            "weight": 0.35
        })
        confidence_signals.append(0.75)

    # 5. Suspicious attachments
    for att in attachments:
        att_ext = os.path.splitext(att)[1].lower()
        if att_ext in [".exe", ".scr", ".iso", ".vbs", ".js", ".hta", ".bat", ".cmd", ".ps1", ".xlsm", ".docm"]:
            evidence.append({
                "description": f"Suspicious executable or macro-enabled attachment detected: '{att}'",
                "field_ref": "attachments",
                "weight": 0.45
            })
            confidence_signals.append(0.85)

    # Compute overall confidence
    if confidence_signals:
        # Asymptotic combination: 1 - prod(1 - c_i)
        prod = 1.0
        for c in confidence_signals:
            capped = min(max(c, 0.1), 0.95)
            prod *= (1.0 - capped)
        raw_confidence = 1.0 - prod
        confidence = round(min(max(raw_confidence, 0.45), 0.98), 2)
        event_type = "phishing_email_detected"
    else:
        confidence = 0.10
        event_type = "email_analyzed_clean"
        evidence.append({
            "description": "Email headers and body content parsed; no malicious phishing indicators discovered.",
            "field_ref": "body_text",
            "weight": 0.0
        })

    # Prepare entities dictionary
    entities: Dict[str, Any] = {}
    if recipient_email:
        entities["user_email"] = recipient_email
    elif sender_email:
        entities["user_email"] = sender_email
        
    if sender_domain:
        entities["domain"] = sender_domain
    elif extracted_urls:
        try:
            entities["domain"] = urllib.parse.urlparse(extracted_urls[0]).netloc
        except Exception:
            pass

    if extracted_urls:
        entities["url"] = extracted_urls[0]

    entities["campaign_id"] = None

    return {
        "event_id": f"evt_{uuid.uuid4()}",
        "source_engine": "email",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "confidence": confidence,
        "entities": entities,
        "iocs": iocs,
        "evidence": evidence,
        "raw_reference": file_path if file_path else "uploads/unknown.eml",
        "mitre_technique": None,
        "risk_level": None,
        "response_recommended": None
    }
