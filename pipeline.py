from __future__ import annotations
import json
from typing import Any
from sqlalchemy.orm import Session
from app.db import init_db
from app.models import Case
from app.modules.correlation import persist_indicators
from app.modules.forensics import analyze_headers
from app.modules.intel import collect_iocs, enrich
from app.modules.ml import score_content
from app.modules.parser import parse_eml
from app.modules.report import forensic_report
from app.modules.scoring import risk_assessment
def run_pipeline(db: Session, raw: bytes, filename: str) -> dict[str, Any]:
    init_db()
    parsed = parse_eml(raw)
    forensics = analyze_headers(parsed)
    ml = score_content(parsed)
    iocs = collect_iocs(parsed, forensics)
    intel = enrich(iocs)
    risk = risk_assessment(forensics, ml, intel)
    case = Case(
        filename=filename,
        subject=parsed.get("subject") or "",
        from_addr=parsed.get("from_addr") or "",
        classification=risk["classification"],
        risk_score=risk["score"],
        result_json="{}",
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    persist_indicators(db, case.id, iocs)
    result = {
        "case_id": case.id,
        "parsed": _public_parsed(parsed),
        "forensics": forensics,
        "ml": ml,
        "iocs": iocs,
        "intel": intel,
        "risk": risk,
    }
    result["report_markdown"] = forensic_report(result)
    case.result_json = json.dumps(result, default=str)
    db.commit()
    return result
def _public_parsed(parsed: dict[str, Any]) -> dict[str, Any]:
    keep = {k: parsed[k] for k in parsed if k != "headers"}
    keep["header_keys"] = sorted((parsed.get("headers") or {}).keys())
    keep["headers"] = parsed.get("headers") or {}
    return keep
