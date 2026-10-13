from __future__ import annotations

ATTACK_TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "subtechnique_of": "T1059",
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "subtechnique_of": "T1059",
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "subtechnique_of": "T1059",
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1087/",
    },
    "T1087.001": {
        "name": "Local Account",
        "tactic": "Discovery",
        "subtechnique_of": "T1087",
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1087/001/",
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1210/",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1005/",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "subtechnique_of": "T1071",
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "subtechnique_of": None,
        "source": "MITRE ATT&CK Enterprise",
        "source_url": "https://attack.mitre.org/techniques/T1041/",
    },
}

CWE_CAPEC_MAPPINGS = {
    "CWE-79": [
        {
            "capec_id": "CAPEC-63",
            "capec_name": "Cross-Site Scripting (XSS)",
            "mapping_confidence": "confirmed",
            "mapping_source": "MITRE CAPEC Related Weaknesses",
            "mapping_rationale": "CAPEC-63 explicitly lists CWE-79 as a related weakness.",
            "source_url": "https://capec.mitre.org/data/definitions/63.html",
        }
    ],
    "CWE-89": [
        {
            "capec_id": "CAPEC-66",
            "capec_name": "SQL Injection",
            "mapping_confidence": "confirmed",
            "mapping_source": "MITRE CAPEC Related Weaknesses",
            "mapping_rationale": "CAPEC-66 explicitly lists CWE-89 as a related weakness.",
            "source_url": "https://capec.mitre.org/data/definitions/66.html",
        }
    ],
    "CWE-78": [
        {
            "capec_id": "CAPEC-88",
            "capec_name": "OS Command Injection",
            "mapping_confidence": "confirmed",
            "mapping_source": "MITRE CAPEC Related Weaknesses",
            "mapping_rationale": "CAPEC-88 explicitly lists CWE-78 as a related weakness.",
            "source_url": "https://capec.mitre.org/data/definitions/88.html",
        }
    ],
    "CWE-22": [
        {
            "capec_id": "CAPEC-126",
            "capec_name": "Path Traversal",
            "mapping_confidence": "confirmed",
            "mapping_source": "MITRE CAPEC Related Weaknesses",
            "mapping_rationale": "CAPEC-126 explicitly lists CWE-22 as a related weakness.",
            "source_url": "https://capec.mitre.org/data/definitions/126.html",
        }
    ],
}

POTENTIAL_TECHNIQUE_MAPPINGS = {
    ("cwe", "CWE-79"): [
        {
            "attack_id": "T1190",
            "mapping_confidence": "low confidence",
            "mapping_source": "VulnForge curated contextual mapping",
            "mapping_rationale": (
                "A web application weakness could be exploited for Initial Access if the affected "
                "application is externally reachable. The CWE alone does not prove exploitation or ATT&CK activity."
            ),
        }
    ],
    ("cwe", "CWE-89"): [
        {
            "attack_id": "T1190",
            "mapping_confidence": "medium confidence",
            "mapping_source": "VulnForge curated contextual mapping",
            "mapping_rationale": (
                "SQL injection in a public-facing application can be relevant to Exploit Public-Facing Application. "
                "This is potential behaviour only; vulnerability presence does not prove that T1190 occurred."
            ),
        }
    ],
    ("cwe", "CWE-78"): [
        {
            "attack_id": "T1059",
            "mapping_confidence": "medium confidence",
            "mapping_source": "VulnForge curated contextual mapping",
            "mapping_rationale": (
                "OS command injection can enable command execution through a command/scripting interpreter. "
                "The weakness alone does not prove command execution was observed."
            ),
        }
    ],
    ("capec", "CAPEC-88"): [
        {
            "attack_id": "T1059",
            "mapping_confidence": "medium confidence",
            "mapping_source": "VulnForge curated contextual mapping",
            "mapping_rationale": (
                "CAPEC-88 describes OS command injection, which can lead to command interpreter execution. "
                "This mapping is contextual and remains potential without behavioural telemetry."
            ),
        }
    ],
}


def get_capec_for_cwe(cwe_id: str) -> list[dict]:
    return list(CWE_CAPEC_MAPPINGS.get(cwe_id.upper(), []))


def get_potential_techniques(subject_type: str, subject_id: str) -> list[dict]:
    return list(POTENTIAL_TECHNIQUE_MAPPINGS.get((subject_type.lower(), subject_id.upper()), []))


def get_attack_technique(attack_id: str) -> dict | None:
    return ATTACK_TECHNIQUES.get(attack_id.upper())
