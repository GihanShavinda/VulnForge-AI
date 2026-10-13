from __future__ import annotations
import json, re
import xml.etree.ElementTree as ET

def _row(category, value, locator, raw, confidence="high confidence"):
    return {"category":category,"observed_value":str(value),"source_locator":locator,"confidence":confidence,"raw":raw}

def parse_testssl(payload):
    data=json.loads(payload) if isinstance(payload,str) else payload
    rows=data if isinstance(data,list) else data.get("scanResult",data.get("results",[])) if isinstance(data,dict) else []
    out=[]
    for item in rows or []:
        if not isinstance(item,dict): continue
        tid=str(item.get("id") or item.get("test") or "").lower()
        finding=str(item.get("finding") or item.get("result") or item.get("status") or "")
        mapping={
            "sslv2":"protocol.sslv2","sslv3":"protocol.sslv3",
            "tls1_1":"protocol.tls1_1","tls1":"protocol.tls1_0",
            "cert_expiration":"certificate.expired","certificate_expiration":"certificate.expired",
            "cert_hostmatch":"certificate.hostname_mismatch","cert_selfsigned":"certificate.self_signed",
            "cert_trust":"certificate.trust","cert_chain":"certificate.chain_issue",
        }
        for key,cat in mapping.items():
            if key in tid:
                out.append(_row(cat,finding or "true",tid,item))
                break
        if "cipher" in tid and any(x in finding.lower() for x in ["weak","insecure","deprecated"]):
            out.append(_row("cipher.weak",finding,tid,item))
        if "renegotiation" in tid and "insecure" in finding.lower():
            out.append(_row("renegotiation.insecure","true",tid,item))
        if "key" in tid:
            m=re.search(r"\b(\d{3,5})\b",finding)
            if m: out.append(_row("certificate.key_bits",m.group(1),tid,item))
    return out

def parse_sslscan(payload: str):
    root=ET.fromstring(payload)
    out=[]
    for attr,cat in {"ssl2":"protocol.sslv2","ssl3":"protocol.sslv3","tls10":"protocol.tls1_0","tls11":"protocol.tls1_1"}.items():
        val=root.attrib.get(attr)
        if val is not None:
            out.append(_row(cat,"enabled" if str(val).lower() in {"1","true","yes","enabled"} else "disabled",f"sslscan@{attr}",{attr:val},"confirmed"))
    cert=root.find(".//certificate")
    if cert is not None:
        ss=cert.attrib.get("selfSigned") or cert.findtext("selfSigned")
        if ss is not None: out.append(_row("certificate.self_signed","true" if str(ss).lower() in {"1","true","yes"} else "false","certificate.selfSigned",{"selfSigned":ss},"confirmed"))
        bits=cert.attrib.get("keySize") or cert.findtext("keySize")
        if bits: out.append(_row("certificate.key_bits",bits,"certificate.keySize",{"keySize":bits},"confirmed"))
    for cipher in root.findall(".//cipher"):
        status=(cipher.attrib.get("status") or "").lower()
        name=cipher.attrib.get("cipher") or cipher.attrib.get("name") or status
        if status in {"weak","insecure"}:
            out.append(_row("cipher.weak",name,"cipher",dict(cipher.attrib),"confirmed"))
    return out

def parse_nmap_ssl(payload: str):
    root=ET.fromstring(payload)
    out=[]
    for script in root.findall(".//script"):
        sid=script.attrib.get("id","")
        output=script.attrib.get("output","")
        low=output.lower()
        if sid=="ssl-enum-ciphers":
            checks=[("sslv2","protocol.sslv2"),("sslv3","protocol.sslv3"),("tlsv1.1","protocol.tls1_1")]
            for needle,cat in checks:
                if needle in low: out.append(_row(cat,"enabled",sid,{"output":output}))
            if "tlsv1.0" in low or "tlsv1:" in low: out.append(_row("protocol.tls1_0","enabled",sid,{"output":output}))
            weak=[line.strip() for line in output.splitlines() if any(x in line.lower() for x in ["3des","rc4","des-cbc","null cipher","export"])]
            if weak: out.append(_row("cipher.weak","; ".join(weak),sid,{"output":output}))
        elif sid=="ssl-cert":
            if "self-signed" in low: out.append(_row("certificate.self_signed","true",sid,{"output":output}))
            if "expired" in low: out.append(_row("certificate.expired","true",sid,{"output":output}))
            m=re.search(r"Public Key bits:\s*(\d+)",output,re.I)
            if m: out.append(_row("certificate.key_bits",m.group(1),sid,{"output":output}))
    return out

PARSERS={"testssl":parse_testssl,"testssl.sh":parse_testssl,"sslscan":parse_sslscan,"nmap":parse_nmap_ssl,"nmap ssl scripts":parse_nmap_ssl}

def parse_tls_scanner(scanner: str, payload):
    parser=PARSERS.get(scanner.strip().lower())
    if parser is None: raise ValueError(f"Unsupported TLS scanner: {scanner}")
    return parser(payload)
