from __future__ import annotations
import json
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from app.db import active_database_url, get_db, init_db
from app.models import Case
from app.modules.correlation import campaign_graph
from app.pipeline import run_pipeline
ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
init_db()
app = FastAPI(title="Tracepost", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")
@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")
@app.get("/health")
def health():
    return {"ok": True, "database": active_database_url.split("://", 1)[0]}
@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    rows = db.query(Case).order_by(Case.created_at.desc()).limit(50).all()
    return [
        {
            "id": c.id,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "filename": c.filename,
            "subject": c.subject,
            "from_addr": c.from_addr,
            "classification": c.classification,
            "risk_score": c.risk_score,
        }
        for c in rows
    ]
@app.get("/api/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    c = db.get(Case, case_id)
    if not c:
        raise HTTPException(404, "case not found")
    return json.loads(c.result_json)
@app.get("/api/cases/{case_id}/graph")
def get_graph(case_id: str, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "case not found")
    return campaign_graph(db, case_id)
@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty file")
    name = file.filename or "message.eml"
    return run_pipeline(db, raw, name)
@app.post("/api/analyze-samples")
def analyze_samples(db: Session = Depends(get_db)):
    sample_dir = ROOT / "samples"
    out = []
    for path in sorted(sample_dir.glob("*.eml")):
        out.append(run_pipeline(db, path.read_bytes(), path.name)["case_id"])
    return {"case_ids": out}
