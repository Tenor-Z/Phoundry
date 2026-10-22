import re

# Patch levels for php2shell (CVE-2026-109618 / CVE-2026-109619)
PATCH_THRESHOLDS = {
    8.5: 12,
    8.4: 27,
    8.3: 36,
    8.2: 35
}

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfuid"],
    "aws": ["awselb", "aws-waf"],
    "akamai": ["akamai-extension", "aka-edge"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "modsecurity": ["mod_security", "modsecurity"]
}

def detect_waf(headers: dict) -> str | None:
    """Analyzes raw headers for signs of a security reverse proxy / WAF."""
    header_keys_lower = [k.lower() for k in headers.keys()]
    header_values_lower = [str(v).lower() for v in headers.values()]
    
    for waf_name, markers in WAF_SIGNATURES.items():
        for marker in markers:
            if any(marker in k for k in header_keys_lower) or any(marker in v for v in header_values_lower):
                return waf_name.upper()
    return None

def parse_php_version(header_string: str) -> str | None:
    """Extracts raw PHP version numbers out of noisy server strings."""
    match = re.search(r"PHP/([0-9.]+)", header_string, re.IGNORECASE)
    if not match:
        match = re.search(r"PHP\s+([0-9.]+)", header_string, re.IGNORECASE)
    return match.group(1) if match else None

def evaluate_vulnerability(version_str: str) -> tuple[str, str]:
    """Determines security verdict based on target version strings."""
    try:
        # Check for distribution backport flags (e.g., ubuntu, debian) which introduce ambiguity
        is_backported = any(pkg in version_str.lower() for pkg in ["ubuntu", "deb", "rhel", "pve"])
        
        parts = [int(p) for p in version_str.split('.') if p.isdigit()]
        if len(parts) < 2:
            return "Unknown", "Incomplete version architecture."

        major, minor = parts[0], parts[1]
        patch = parts[2] if len(parts) > 2 else 0

        if major < 8:
            return "Legacy EOL", f"PHP {version_str} is deprecated and fundamentally vulnerable."

        if major == 8:
            # Handle distribution specific vendor configurations
            backport_suffix = " (Note: OS vendor may have backported the security patch)" if is_backported else ""
            
            major_minor = float(f"{major}.{minor}")
            if major_minor in PATCH_THRESHOLDS:
                safe_patch = PATCH_THRESHOLDS[major_minor]
                if patch < safe_patch:
                    return "Vulnerable", f"Version below required patch ({major}.{minor}.{safe_patch}){backport_suffix}."
                return "Safe", f"Version meets secure baseline ({major}.{minor}.{safe_patch})."
            elif major_minor > 8.5:
                return "Safe", f"Running modern stable branch release."
            else:
                return "Vulnerable", f"Branch {major}.{minor} is fully deprecated and unpatched."

        return "Unknown", "Unrecognized PHP architecture generation."
    except Exception as e:
        return "Error", f"Parsing exception: {str(e)}"
