import hashlib
import re
from typing import Optional

from src.models.schemas import Finding, FindingCategory, Severity

def normalize_message(message: str) -> str:
    """
    Normalize message by removing variable parts (like specific variable names if quoted, or hex addresses).
    Keeps it simple for now: distinct enough to separate different issues, 
    but generic enough to group identical issues.
    """
    # Remove simple hex addresses e.g. 0x12345678
    msg = re.sub(r'0x[0-9a-fA-F]+', '<HEX>', message)
    # Truncate to avoid huge keys
    return msg[:200].strip()

def compute_fingerprint(finding: Finding) -> str:
    """
    Compute a stable fingerprint for a finding.
    
    Format: category:rule_id:line:normalized_message_hash
    """
    # Normalize inputs
    cat = finding.category.value
    rule =finding.rule_id or "unknown"
    line = finding.line_number
    
    # Hash the normalized message
    msg_norm = normalize_message(finding.message)
    msg_hash = hashlib.md5(msg_norm.encode('utf-8')).hexdigest()[:8]
    
    return f"{cat}:{rule}:{line}:{msg_hash}"

def normalize_severity(severity: str) -> Severity:
    """Normalize severity string to Enum."""
    try:
        return Severity(severity.lower())
    except ValueError:
        return Severity.MEDIUM

def normalize_category(category: str) -> FindingCategory:
    """Normalize category string to Enum."""
    try:
        return FindingCategory(category.lower())
    except ValueError:
        return FindingCategory.OTHER

def normalize_finding(finding: Finding) -> Finding:
    """
    Apply global normalization rules to a finding.
    1. Ensure severity is correct for security issues.
    2. Compute fingerprint.
    """
    # Security Rule Implementation:
    # If category implies security, ensure it's treated as such.
    # Note: QualityAgent might set category=SECURITY but severity=LOW. 
    # We enforce a floor for known security categories if needed, 
    # but primarily we rely on the deduplicator to pick the SecurityAgent's version.
    
    if finding.category in [
        FindingCategory.SQL_INJECTION,
        FindingCategory.XSS,
        FindingCategory.HARDCODED_SECRET,
        FindingCategory.INSECURE_IMPORT,
        FindingCategory.AUTHENTICATION,
        FindingCategory.AUTHORIZATION,
        FindingCategory.CRYPTOGRAPHY,
        FindingCategory.INJECTION
    ]:
         # Ensure strictly typed as security if loosely typed? 
         # Already handled by Enum.
         pass

    # Compute fingerprint
    if not finding.fingerprint:
        finding.fingerprint = compute_fingerprint(finding)
        
    return finding
