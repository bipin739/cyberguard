import os
import re
from pathlib import Path

# Regular expressions for text content sniffing
EMAIL_HEADER_REGEX = re.compile(
    r"^(from|to|subject|received|date|message-id|return-path|mime-version|reply-to|delivered-to):\s*",
    re.IGNORECASE | re.MULTILINE
)

# Network log patterns: Timestamps + IP addresses or standard auth/web log lines
IPV4_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
TIMESTAMP_REGEX = r"(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"

LOG_LINE_REGEX = re.compile(
    rf"(?:{TIMESTAMP_REGEX}.*?{IPV4_REGEX}|{IPV4_REGEX}.*?{TIMESTAMP_REGEX}|\b(?:sshd|kernel|systemd|firewall|nginx|apache2|auditd|named|dhcpd)\[\d+\]:.*{IPV4_REGEX})",
    re.IGNORECASE
)

NETWORK_CSV_HEADER_REGEX = re.compile(
    r"\b(src_ip|dst_ip|source_ip|destination_ip|ip_address|client_ip|src_port|dst_port|proto|protocol|packet_len|flow_duration|bytes_in|bytes_out)\b",
    re.IGNORECASE
)

URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


def detect_file_type(file_path: str) -> str:
    """
    Detects the file type using manual magic bytes, text content sniffing,
    and extension fallback. Does NOT require libmagic or external C binaries.

    Returns one of:
      - 'email'
      - 'malware'
      - 'deepfake_audio'
      - 'deepfake_video'
      - 'network'
      - 'url'
      - 'unknown'
    """
    if not os.path.exists(file_path):
        return "unknown"

    # Step 1 & 2: Magic Byte Inspection
    raw_header = b""
    try:
        with open(file_path, "rb") as f:
            raw_header = f.read(64)
    except Exception:
        return "unknown"

    ext = Path(file_path).suffix.lower()

    if len(raw_header) >= 2:
        # Windows PE Executable (.exe, .dll, .sys)
        if raw_header.startswith(b"MZ"):
            return "malware"

        # Linux ELF Executable
        if raw_header.startswith(b"\x7fELF"):
            return "malware"

        # Mach-O Executables
        if (
            raw_header.startswith(b"\xfe\xed\xfa\xce")
            or raw_header.startswith(b"\xfe\xed\xfa\xcf")
            or raw_header.startswith(b"\xce\xfa\xed\xfe")
            or raw_header.startswith(b"\xcf\xfa\xed\xfe")
            or raw_header.startswith(b"\xca\xfe\xba\xbe")
        ):
            return "malware"

        # ZIP-based containers (ZIP, DOCX, XLSX, etc.) -> unknown (no dedicated doc engine yet)
        if raw_header.startswith(b"PK\x03\x04") or raw_header.startswith(b"PK\x05\x06") or raw_header.startswith(b"PK\x07\x08"):
            return "unknown"

        # PDF documents -> unknown (no dedicated doc engine yet)
        if raw_header.startswith(b"%PDF"):
            return "unknown"

        # PNG image (treated as deepfake_video frame)
        if raw_header.startswith(b"\x89PNG"):
            return "deepfake_video"

        # JPEG image (treated as deepfake_video frame)
        if raw_header.startswith(b"\xff\xd8\xff"):
            return "deepfake_video"

        # GIF image
        if raw_header.startswith(b"GIF87a") or raw_header.startswith(b"GIF89a"):
            return "deepfake_video"

        # MP3 audio (ID3 header or sync frames)
        if (
            raw_header.startswith(b"ID3")
            or raw_header.startswith(b"\xff\xfb")
            or raw_header.startswith(b"\xff\xf3")
            or raw_header.startswith(b"\xff\xf2")
        ):
            return "deepfake_audio"

        # WAV or AVI or WebP (RIFF container)
        if raw_header.startswith(b"RIFF") and len(raw_header) >= 12:
            riff_type = raw_header[8:12]
            if riff_type == b"WAVE":
                return "deepfake_audio"
            elif riff_type == b"AVI ":
                return "deepfake_video"
            elif riff_type == b"WEBP":
                return "deepfake_video"

        # FLAC audio
        if raw_header.startswith(b"fLaC"):
            return "deepfake_audio"

        # OGG audio/video container
        if raw_header.startswith(b"OggS"):
            return "deepfake_audio"

        # MP4 / QuickTime / ISO Base Media File (ftyp signature at byte 4)
        if len(raw_header) >= 8 and raw_header[4:8] in (b"ftyp", b"moov", b"mdat"):
            return "deepfake_video"

        # Matroska / WebM video
        if raw_header.startswith(b"\x1a\x45\xdf\xa3"):
            return "deepfake_video"

        # PCAP / PCAPNG network captures
        if (
            raw_header.startswith(b"\xd4\xc3\xb2\xa1")
            or raw_header.startswith(b"\xa1\xb2\xc3\xd4")
            or raw_header.startswith(b"\x4d\x3c\xb2\xa1")
            or raw_header.startswith(b"\xa1\xb2\x3c\x4d")
            or raw_header.startswith(b"\n\r\r\n")
        ):
            return "network"

        # MS Outlook .msg binary (Compound File Binary Format)
        if raw_header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "email"

    # Step 3: Content Sniffing for Plain Text / Logs / Scripts / EML
    text_content = ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read(65536)
    except Exception:
        try:
            with open(file_path, "r", encoding="latin-1", errors="ignore") as f:
                text_content = f.read(65536)
        except Exception:
            text_content = ""

    if text_content:
        # Check for Email headers
        email_matches = EMAIL_HEADER_REGEX.findall(text_content)
        if len(email_matches) >= 2 or (len(email_matches) >= 1 and any(h.lower() in ("from", "subject", "received") for h in email_matches)):
            return "email"

        # Check for URL
        stripped = text_content.strip()
        if URL_REGEX.match(stripped) or (stripped.startswith("[InternetShortcut]") and "URL=" in stripped):
            return "url"

        # Check for Network / Auth / Syslog log lines
        lines = text_content.splitlines()[:100]
        log_hits = 0
        for line in lines:
            if LOG_LINE_REGEX.search(line):
                log_hits += 1
            if log_hits >= 1:
                return "network"

        # Check for CSV network header
        if lines and NETWORK_CSV_HEADER_REGEX.search(lines[0]):
            return "network"

    # Step 5: Secondary Extension Fallback (Only when byte signature & text sniffing are inconclusive)
    extension_map = {
        ".eml": "email",
        ".msg": "email",
        ".exe": "malware",
        ".dll": "malware",
        ".sys": "malware",
        ".mp3": "deepfake_audio",
        ".wav": "deepfake_audio",
        ".ogg": "deepfake_audio",
        ".flac": "deepfake_audio",
        ".m4a": "deepfake_audio",
        ".aac": "deepfake_audio",
        ".mp4": "deepfake_video",
        ".avi": "deepfake_video",
        ".mov": "deepfake_video",
        ".mkv": "deepfake_video",
        ".webm": "deepfake_video",
        ".jpg": "deepfake_video",
        ".jpeg": "deepfake_video",
        ".png": "deepfake_video",
        ".webp": "deepfake_video",
        ".pcap": "network",
        ".pcapng": "network",
        ".cap": "network",
        ".log": "network",
        ".csv": "network"
    }

    if ext in extension_map:
        return extension_map[ext]

    return "unknown"
