from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import Case, Indicator


def persist_indicators(db: Session, case_id: str, iocs: dict[str, list[str]]) -> None:
    db.query(Indicator).filter(Indicator.case_id == case_id).delete()
    for kind, values in iocs.items():
        for value in values:
            db.add(Indicator(case_id=case_id, kind=kind, value=value[:1024]))
    db.commit()


def campaign_graph(db: Session, case_id: str) -> dict[str, Any]:
    mine = db.query(Indicator).filter(Indicator.case_id == case_id).all()
    nodes = {"case:" + case_id: {"id": "case:" + case_id, "type": "case", "label": "This case"}}
    edges = []

    for ind in mine:
        nid = f"{ind.kind}:{ind.value}"
        nodes[nid] = {"id": nid, "type": ind.kind, "label": ind.value}
        edges.append({"from": "case:" + case_id, "to": nid})

        others = (
            db.query(Indicator)
            .filter(Indicator.value == ind.value, Indicator.kind == ind.kind, Indicator.case_id != case_id)
            .all()
        )
        for o in others:
            cid = "case:" + o.case_id
            other = db.get(Case, o.case_id)
            label = (other.subject[:48] + "…") if other and other.subject else o.case_id[:8]
            nodes[cid] = {"id": cid, "type": "case", "label": label}
            edges.append({"from": cid, "to": nid})

    shared = [n for n in nodes.values() if n["type"] != "case" and sum(1 for e in edges if e["to"] == n["id"]) > 1]
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "shared_infrastructure": shared,
        "story": "If two messages share an IP or sending domain, treat that as campaign infrastructure — not proof of the same person.",
    }
