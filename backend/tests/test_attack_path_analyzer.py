from app.services.attack_path_analyzer import analyze_path


def _confirmed_edge(
    rel_type,
    source="VulnForge evidence",
    details=None,
    privilege=False,
):
    return {
        "relationship_type": rel_type,
        "properties": {
            "evidence_status": "confirmed",
            "confidence": "confirmed",
            "source": source,
            "details": details or {},
            "privilege_increase": privilege,
        },
    }


def test_all_confirmed_edges_produce_evidence_confirmed_path():
    raw = {
        "nodes": [
            {
                "key": "scenario:kali-lab-attacker",
                "name": "Kali",
                "labels": ["Asset"],
                "properties": {
                    "exposure": "lab",
                },
            },
            {
                "key": "asset:web",
                "name": "Web Server",
                "labels": ["Asset"],
                "properties": {},
            },
            {
                "key": "service:http",
                "name": "HTTP",
                "labels": ["Service"],
                "properties": {},
            },
            {
                "key": "asset:db",
                "name": "Database",
                "labels": ["SensitiveAsset"],
                "properties": {
                    "critical": True,
                    "high_value": True,
                },
            },
        ],
        "relationships": [
            _confirmed_edge(
                "REACHABLE_FROM"
            ),
            _confirmed_edge(
                "EXPOSES"
            ),
            _confirmed_edge(
                "CAN_ACCESS"
            ),
        ],
    }

    result = analyze_path(
        raw
    )

    assert (
        result.path_status
        == "evidence-confirmed"
    )

    assert result.path_length == 3
    assert result.critical_destination is True
    assert (
        result.reachable_high_value_asset
        is True
    )


def test_one_theoretical_edge_makes_whole_path_theoretical():
    raw = {
        "nodes": [
            {
                "key": "scenario:internet",
                "name": "Internet",
                "labels": [
                    "TrustBoundary"
                ],
                "properties": {
                    "exposure": "external",
                },
            },
            {
                "key": "asset:web",
                "name": "Web",
                "labels": ["Asset"],
                "properties": {},
            },
            {
                "key": "asset:db",
                "name": "DB",
                "labels": [
                    "SensitiveAsset"
                ],
                "properties": {
                    "high_value": True,
                },
            },
        ],
        "relationships": [
            _confirmed_edge(
                "REACHABLE_FROM"
            ),
            {
                "relationship_type": (
                    "CAN_ACCESS"
                ),
                "properties": {
                    "evidence_status": (
                        "theoretical"
                    ),
                    "confidence": (
                        "medium confidence"
                    ),
                    "source": (
                        "derived graph reasoning"
                    ),
                    "details": {},
                },
            },
        ],
    }

    result = analyze_path(
        raw
    )

    assert (
        result.path_status
        == "theoretical"
    )

    assert (
        result.confidence_score
        < 1.0
    )

    assert (
        "does not confirm exploitation"
        in result.rationale
    )


def test_credential_dependency_and_privilege_increase():
    raw = {
        "nodes": [
            {
                "key": "user:low",
                "name": (
                    "Low Privilege User"
                ),
                "labels": [
                    "UserRole"
                ],
                "properties": {
                    "exposure": "internal",
                },
            },
            {
                "key": "cred:db",
                "name": (
                    "Database Credential"
                ),
                "labels": [
                    "Credential"
                ],
                "properties": {},
            },
            {
                "key": "db:critical",
                "name": (
                    "Critical DB"
                ),
                "labels": [
                    "SensitiveAsset"
                ],
                "properties": {
                    "critical": True,
                },
            },
        ],
        "relationships": [
            _confirmed_edge(
                "HAS_CREDENTIAL"
            ),
            _confirmed_edge(
                "AUTHENTICATES_TO",
                privilege=True,
            ),
        ],
    }

    result = analyze_path(
        raw
    )

    assert (
        result.credential_dependency
        is True
    )

    assert (
        result.privilege_increase
        is True
    )


def test_enabling_findings_and_weak_control():
    raw = {
        "nodes": [
            {
                "key": "asset:web",
                "name": "Web",
                "labels": ["Asset"],
                "properties": {
                    "exposure": "external",
                },
            },
            {
                "key": "vuln:1",
                "name": (
                    "Vulnerability"
                ),
                "labels": [
                    "Vulnerability"
                ],
                "properties": {},
            },
            {
                "key": "control:waf",
                "name": "WAF",
                "labels": [
                    "SecurityControl"
                ],
                "properties": {
                    "strength": "weak",
                },
            },
        ],
        "relationships": [
            _confirmed_edge(
                "HAS_VULNERABILITY"
            ),
            _confirmed_edge(
                "PROTECTED_BY"
            ),
        ],
    }

    result = analyze_path(
        raw
    )

    assert (
        result.enabling_findings
        >= 1
    )

    assert (
        result.weakest_control
        == "WAF"
    )


def test_serialized_edge_details_restore_privilege_information():
    raw = {
        "nodes": [
            {
                "key": (
                    "credential:demo"
                ),
                "name": (
                    "Credential"
                ),
                "labels": [
                    "Credential"
                ],
                "properties": {
                    "exposure": (
                        "internal"
                    )
                },
            },
            {
                "key": (
                    "sensitive:db"
                ),
                "name": (
                    "Database"
                ),
                "labels": [
                    "SensitiveAsset"
                ],
                "properties": {
                    "critical": True,
                    "high_value": True,
                },
            },
        ],
        "relationships": [
            {
                "relationship_type": (
                    "AUTHENTICATES_TO"
                ),
                "properties": {
                    "evidence_status": (
                        "confirmed"
                    ),
                    "confidence": (
                        "confirmed"
                    ),
                    "source": (
                        "test evidence"
                    ),
                    "details_json": (
                        '{"privilege_increase": true}'
                    ),
                },
            }
        ],
    }

    result = analyze_path(
        raw
    )

    assert (
        result.credential_dependency
        is True
    )

    assert (
        result.privilege_increase
        is True
    )

    assert (
        result.evidence[0]["details"]
        == {
            "privilege_increase": True
        }
    )