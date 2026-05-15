"""
Scanner-specific field name mappings → internal Finding schema.
Each entry maps scanner CSV column names to internal field names.
"""

NESSUS_MAP = {
    "title":                 ["Name", "Plugin Name", "Vulnerability"],
    "summary":               ["Synopsis", "Summary"],
    "description":           ["Description", "Details"],
    "impact":                ["Plugin Output", "Impact"],
    "recommendation":        ["Solution", "Recommendation", "Remediation"],
    "cvss.score":            ["CVSS v2 Base Score", "CVSS Base Score", "CVSS Score", "CVSSv3 Base Score"],
    "cvss.vector":           ["CVSSv3 Vector", "CVSS Vector", "CVSS v3 Vector"],
    "cvss.level":            ["Risk", "Severity"],
    "cwe":                   ["CWE"],
    "affected_components":   ["Host", "IP", "URL", "Hostname"],
    "poc":                   ["Plugin Output"],
    "references":            ["See Also", "References", "CVE"],
}

OPENVAS_MAP = {
    "title":                 ["Vulnerability", "NVT Name", "Name"],
    "summary":               ["Summary", "Synopsis"],
    "description":           ["Description", "Specific Result"],
    "impact":                ["Impact", "Insight"],
    "recommendation":        ["Solution", "Fix"],
    "cvss.score":            ["CVSS Base Score", "CVSS Score", "Severity"],
    "cvss.vector":           ["CVSS Vector"],
    "cvss.level":            ["Severity Class", "Severity", "Risk"],
    "cwe":                   ["CWE", "CVE"],
    "affected_components":   ["Host", "Port", "IP"],
    "poc":                   ["Specific Result", "Evidence"],
    "references":            ["References", "URL"],
}

BURP_MAP = {
    "title":                 ["Issue name", "Name", "Type"],
    "summary":               ["Issue background", "Summary"],
    "description":           ["Issue detail", "Description"],
    "impact":                ["Vulnerability classifications", "Impact"],
    "recommendation":        ["Remediation background", "Remediation", "Fix"],
    "cvss.score":            ["CVSS Score", "Severity Score"],
    "cvss.vector":           ["CVSS Vector"],
    "cvss.level":            ["Severity", "Risk"],
    "cwe":                   ["CWE"],
    "affected_components":   ["URL", "Host", "Path"],
    "poc":                   ["Request", "Evidence"],
    "references":            ["References", "External references"],
}

GENERIC_MAP = {
    "title":                 ["title", "name", "vulnerability", "finding", "issue"],
    "summary":               ["summary", "synopsis", "brief"],
    "description":           ["description", "details", "detail", "body"],
    "impact":                ["impact", "business_impact", "effect"],
    "recommendation":        ["recommendation", "solution", "remediation", "fix", "mitigation"],
    "cvss.score":            ["cvss_score", "cvss score", "score", "cvss", "base_score"],
    "cvss.vector":           ["cvss_vector", "cvss vector", "vector"],
    "cvss.level":            ["severity", "risk", "level", "cvss_level", "criticality"],
    "cwe":                   ["cwe", "cwe_id", "weakness"],
    "affected_components":   ["host", "url", "ip", "endpoint", "component", "affected_url", "target"],
    "poc":                   ["poc", "proof_of_concept", "steps", "reproduction", "evidence"],
    "references":            ["references", "refs", "see_also", "links", "cve"],
}

# Severity label normalisation — map scanner values to internal levels
SEVERITY_NORMALISE = {
    # critical
    "critical": "critical",
    "crit": "critical",
    "p1": "critical",
    "urgent": "critical",

    # high
    "high": "high",
    "h": "high",
    "p2": "high",
    "important": "high",

    # medium
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "m": "medium",
    "p3": "medium",
    "warning": "medium",

    # low
    "low": "low",
    "l": "low",
    "p4": "low",
    "minor": "low",

    # info
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
    "note": "info",
    "best practice": "info",
    "p5": "info",
}

# Ease of exploit normalisation
EASE_NORMALISE = {
    "trivial": "Trivial",
    "easy": "Trivial",
    "simple": "Trivial",
    "moderate": "Moderate",
    "medium": "Moderate",
    "difficult": "Difficult",
    "hard": "Difficult",
    "complex": "Difficult",
}
