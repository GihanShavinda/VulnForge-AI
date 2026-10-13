from app.services.gitleaks_parser import parse_gitleaks

def test_parse_gitleaks_candidate():
    rows=parse_gitleaks([{"RuleID":"generic-api-key","File":"app.env","StartLine":5,"Secret":"abc123456789-secret"}])
    assert len(rows)==1
    assert rows[0]["secret_type"]=="api_key"
