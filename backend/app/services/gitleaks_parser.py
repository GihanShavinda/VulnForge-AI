from __future__ import annotations
import json

def parse_gitleaks(payload) -> list[dict]:
    data=json.loads(payload) if isinstance(payload,str) else payload
    rows=[]
    for item in data or []:
        if not isinstance(item,dict):
            continue
        secret=item.get("Secret")
        if not secret:
            continue
        path=item.get("File") or "unknown"
        line=item.get("StartLine") or item.get("Line")
        loc=f"{path}:{line}" if line else str(path)
        rule=str(item.get("RuleID") or "gitleaks").lower()
        secret_type=(
            "ssh_private_key" if "ssh" in rule and "private" in rule else
            "private_key" if "private-key" in rule else
            "cloud_credential_pattern" if "aws" in rule else
            "database_connection_string" if "database" in rule or "connection" in rule else
            "jwt_secret" if "jwt" in rule else
            "api_key" if "api" in rule else
            "token"
        )
        severity="Critical" if secret_type in {"private_key","ssh_private_key","cloud_credential_pattern"} else "High"
        rows.append({"secret_type":secret_type,"secret":str(secret),"severity":severity,"location":loc,"validation_status":"scanner-reported"})
    return rows
