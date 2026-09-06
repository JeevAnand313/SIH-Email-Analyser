from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from app.config import settings
from app.modules.parser import domains_from_email, url_host


def collect_iocs(parsed: dict[str, Any], forensics: dict[str, Any]) -> dict[str, list[str]]:
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()

    for hop in forensics.get("hops") or []:
        for ip in hop.get("all_ips") or []:
            if _public_ip(ip):
                ips.add(ip)
    if forensics.get("originating_ip_candidate") and _public_ip(forensics["originating_ip_candidate"]):
        ips.add(forensics["originating_ip_candidate"])

    for key in ("from_addr", "reply_to", "return_path"):
        addr = parsed.get(key) or ""
        if addr:
            emails.add(addr)
            d = domains_from_email(addr)
            if d:
                domains.add(d)

    urls = parsed.get("urls") or []
    for u in urls:
        h = url_host(u)
        if h:
            domains.add(h)

    return {
        "ip": sorted(ips),
        "domain": sorted(domains),
        "url": urls,
        "email": sorted(emails),
    }


def enrich(iocs: dict[str, list[str]]) -> dict[str, Any]:
    ip_rows = []
    if settings.intel_enabled:
        for ip in iocs.get("ip") or []:
            ip_rows.append(lookup_ip(ip))
    else:
        ip_rows = [{"ip": ip, "status": "skipped"} for ip in iocs.get("ip") or []]

    return {
        "ips": ip_rows,
        "domains": [{"domain": d} for d in iocs.get("domain") or []],
        "cannot_determine": [
            "Physical location of a person (VPN, NAT, cloud, compromised hosts).",
            "Whether an IP was the attacker’s machine vs a forwarding MTA.",
            "WHOIS privacy-redacted registrant identity.",
            "Future infrastructure the actor will use.",
        ],
        "can_determine": [
            "ASN / org that announced the IP (when the lookup succeeds).",
            "Country/city estimate from the geo provider — investigative, not attribution.",
            "Whether the host looks like a consumer ISP vs a cloud/VPS range (best-effort from org name).",
        ],
    }


def lookup_ip(ip: str) -> dict[str, Any]:
    token = settings.ipinfo_token.strip()
    try:
        if token:
            r = httpx.get(f"https://ipinfo.io/{ip}/json", params={"token": token}, timeout=8.0)
        else:
            r = httpx.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,message,country,regionName,city,lat,lon,isp,org,as,query,proxy,hosting"}, timeout=8.0)
        r.raise_for_status()
        data = r.json()
        return _normalize(ip, data)
    except Exception as exc:
        return {"ip": ip, "status": "error", "error": str(exc)[:200]}


def _normalize(ip: str, data: dict[str, Any]) -> dict[str, Any]:
    if "ip" in data and "org" in data:
        loc = (data.get("loc") or ",").split(",")
        lat = _f(loc[0]) if loc else None
        lon = _f(loc[1]) if len(loc) > 1 else None
        org = data.get("org") or ""
        return {
            "ip": ip,
            "status": "ok",
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "lat": lat,
            "lon": lon,
            "org": org,
            "asn": org.split(" ", 1)[0] if org.startswith("AS") else None,
            "proxy_or_hosting": None,
            "provider": "ipinfo",
        }
    if data.get("status") == "fail":
        return {"ip": ip, "status": "error", "error": data.get("message")}
    return {
        "ip": data.get("query", ip),
        "status": "ok",
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "org": data.get("org") or data.get("isp"),
        "asn": data.get("as"),
        "proxy_or_hosting": bool(data.get("proxy") or data.get("hosting")),
        "provider": "ip-api",
    }


def _public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_global
    except ValueError:
        return False


def _f(v: str | None) -> float | None:
    try:
        return float(v) if v else None
    except ValueError:
        return None
