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
    "cvss.score":            ["CVSS v2.0 Base Score", "CVSS v3.0 Base Score", "CVSSv3 Base Score", "CVSS v2 Base Score", "CVSS Base Score", "CVSS Score", "CVSSv3.0 Base Score", "CVSSv2.0 Base Score"],
    "cvss.vector":           ["CVSSv3 Vector", "CVSS Vector", "CVSS v3 Vector"],
    "cvss.level":            ["Risk", "Severity"],
    "cwe":                   ["CWE"],
    "affected_components":   ["Host", "IP", "URL", "Hostname"],
    "poc":                   ["Plugin Output"],
    "references":            ["See Also", "References", "CVE"],
    "port":                  ["Port", "Port Number", "Service Port", "Target Port", "Dest Port", "Destination Port", "port_number", "target_port", "dst_port", "p"],
    "protocol":              ["Protocol", "Proto", "Protocol Type", "Port Protocol", "protocol_type", "transport", "prot"],
}

OPENVAS_MAP = {
    "title":                 ["Vulnerability", "NVT Name", "Name"],
    "summary":               ["Summary", "Synopsis"],
    "description":           ["Description", "Specific Result"],
    "impact":                ["Impact", "Insight"],
    "recommendation":        ["Solution", "Fix"],
    "cvss.score":            ["CVSS Base Score", "CVSS Score", "Severity", "CVSS v2.0 Base Score", "CVSS v3.0 Base Score"],
    "cvss.vector":           ["CVSS Vector"],
    "cvss.level":            ["Severity Class", "Severity", "Risk"],
    "cwe":                   ["CWE", "CVE"],
    "affected_components":   ["Host", "Port", "IP"],
    "poc":                   ["Specific Result", "Evidence"],
    "references":            ["References", "URL"],
    "port":                  ["Port", "Port Number", "Service Port", "Target Port", "Dest Port", "Destination Port", "port_number", "target_port", "dst_port", "p"],
    "protocol":              ["Port Protocol", "Protocol", "Proto", "Protocol Type", "protocol_type", "transport", "prot"],
}

BURP_MAP = {
    "title":                 ["Issue name", "Name", "Type"],
    "summary":               ["Issue background", "Summary"],
    "description":           ["Issue detail", "Description"],
    "impact":                ["Vulnerability classifications", "Impact"],
    "recommendation":        ["Remediation background", "Remediation", "Fix"],
    "cvss.score":            ["CVSS Score", "Severity Score", "CVSS v2.0 Base Score", "CVSS v3.0 Base Score"],
    "cvss.vector":           ["CVSS Vector"],
    "cvss.level":            ["Severity", "Risk"],
    "cwe":                   ["CWE"],
    "affected_components":   ["URL", "Host", "Path"],
    "poc":                   ["Request", "Evidence"],
    "references":            ["References", "External references"],
    "port":                  ["Port", "Port Number", "Service Port", "Target Port", "Dest Port", "Destination Port", "port_number", "target_port", "dst_port", "p"],
    "protocol":              ["Protocol", "Proto", "Protocol Type", "Port Protocol", "protocol_type", "transport", "prot"],
}

GENERIC_MAP = {
    "title":                 ["title", "name", "vulnerability", "finding", "issue", "vulnerability name", "plugin name", "issue name", "alert", "threat", "vulnerability_name", "plugin_name"],
    "summary":               ["summary", "synopsis", "brief", "short description", "issue background"],
    "description":           ["description", "details", "detail", "body", "issue detail", "long description", "overview"],
    "impact":                ["impact", "business_impact", "effect", "plugin output", "evidence"],
    "recommendation":        ["recommendation", "solution", "remediation", "fix", "mitigation", "remediation background", "how to fix"],
    "cvss.score":            ["cvss_score", "cvss score", "score", "cvss", "base_score", "cvss v2 base score", "cvss v2.0 base score", "cvss v3.0 base score", "cvssv3 base score", "cvss v3 base score", "severity score"],
    "cvss.vector":           ["cvss_vector", "cvss vector", "vector", "cvssv3 vector", "cvss v3 vector"],
    "cvss.level":            ["severity", "risk", "level", "cvss_level", "criticality", "risk factor", "severity class", "vulnerability severity", "issue severity"],
    "cwe":                   ["cwe", "cwe_id", "weakness", "cwe id"],
    "affected_components":   ["host", "url", "ip", "endpoint", "component", "affected_url", "target", "hostname", "ip address"],
    "poc":                   ["poc", "proof_of_concept", "steps", "reproduction", "evidence", "plugin output", "request", "result"],
    "references":            ["references", "refs", "see_also", "links", "cve", "see also", "cve id"],
    "port":                  ["port", "Port", "Port Number", "Service Port", "Target Port", "Dest Port", "Destination Port", "port_number", "target_port", "dst_port", "p"],
    "protocol":              ["protocol", "Protocol", "Proto", "Protocol Type", "Port Protocol", "protocol_type", "transport", "prot"],
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
