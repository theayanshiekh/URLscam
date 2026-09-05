"""HTTP API."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.models.db_models import FeatureRow, RiskFactor, Scan
from app.schemas.scan import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    ConfigResponse,
    HealthResponse,
    HistoryItem,
    HistoryList,
)
from app.services.analyzer import analyze_url, scan_to_response
from app.services.ml_engine import load_feature_importance, load_metrics, model_available
from app.utils.url_parser import URLParseError

router = APIRouter()


def require_admin(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> None:
    settings = get_settings()
    if not settings.admin_api_key:
        raise HTTPException(status_code=403, detail="Admin API is disabled. Set ADMIN_API_KEY to enable research mode.")
    if not x_admin_key or x_admin_key != settings.admin_api_key:
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        model_loaded=model_available(),
        database="ok",
        redirect_analysis="disabled" if not settings.enable_redirect_analysis else "enabled",
        external_intel={
            "virustotal": bool(settings.virustotal_api_key),
            "google_safe_browsing": bool(settings.google_safe_browsing_key),
            "urlhaus": settings.urlhaus_enabled,
        },
    )


@router.get("/config", response_model=ConfigResponse)
def config() -> ConfigResponse:
    settings = get_settings()
    return ConfigResponse(
        app_name=settings.app_name,
        thresholds={
            "low": settings.threshold_low,
            "medium": settings.threshold_medium,
            "high": settings.threshold_high,
        },
        redirect_analysis_enabled=settings.enable_redirect_analysis,
        external_services={
            "virustotal": bool(settings.virustotal_api_key),
            "google_safe_browsing": bool(settings.google_safe_browsing_key),
        },
        notes=[
            "HTTPS encrypts a connection; it does not prove legitimacy.",
            "Automated URL analysis is probabilistic.",
            "External reputation is used only when API keys are configured and the service responds.",
            "Redirect following is disabled by default to prevent SSRF.",
        ],
    )


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)) -> AnalyzeResponse:
    try:
        return analyze_url(payload.url, db=db, demo=payload.demo)
    except URLParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/analyze/stream")
def analyze_stream(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    def gen():
        queue: list[str] = []

        def on_stage(name: str) -> None:
            queue.append(name)

        try:
            result = analyze_url(payload.url, db=db, demo=payload.demo, on_stage=on_stage)
        except URLParseError as exc:
            yield json.dumps({"event": "error", "detail": str(exc)}) + "\n"
            return
        for name in result.stages:
            yield json.dumps({"event": "stage", "name": name}) + "\n"
        yield json.dumps({"event": "result", "data": json.loads(result.model_dump_json())}) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@router.post("/analyze/batch")
def analyze_batch(payload: BatchAnalyzeRequest, db: Session = Depends(get_db)):
    settings = get_settings()
    if len(payload.urls) > settings.batch_max_urls:
        raise HTTPException(status_code=413, detail=f"Maximum {settings.batch_max_urls} URLs per batch.")
    results = []
    for raw in payload.urls:
        try:
            results.append(analyze_url(raw, db=db).model_dump(mode="json"))
        except URLParseError as exc:
            results.append({"url": raw, "error": str(exc)})
    return {"count": len(results), "results": results}


@router.post("/analyze/csv")
async def analyze_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    settings = get_settings()
    raw = await file.read()
    if len(raw) > settings.batch_max_bytes:
        raise HTTPException(status_code=413, detail="CSV exceeds size limit (1 MB).")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8.") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "url" not in [f.strip().lower() for f in reader.fieldnames]:
        raise HTTPException(status_code=400, detail="CSV must include a 'url' column.")
    urls: list[str] = []
    for row in reader:
        mapping = {k.strip().lower(): v for k, v in row.items() if k}
        url = (mapping.get("url") or "").strip()
        if url:
            urls.append(url)
        if len(urls) >= settings.batch_max_urls:
            break
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in CSV.")
    return analyze_batch(BatchAnalyzeRequest(urls=urls), db)


@router.get("/history", response_model=HistoryList)
def history(
    db: Session = Depends(get_db),
    q: str | None = None,
    classification: str | None = None,
    min_risk: int | None = None,
    max_risk: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
):
    stmt = select(Scan)
    count_stmt = select(func.count(Scan.id))
    if q:
        stmt = stmt.where(Scan.url.contains(q))
        count_stmt = count_stmt.where(Scan.url.contains(q))
    if classification:
        stmt = stmt.where(Scan.classification == classification)
        count_stmt = count_stmt.where(Scan.classification == classification)
    if min_risk is not None:
        stmt = stmt.where(Scan.risk_score >= min_risk)
        count_stmt = count_stmt.where(Scan.risk_score >= min_risk)
    if max_risk is not None:
        stmt = stmt.where(Scan.risk_score <= max_risk)
        count_stmt = count_stmt.where(Scan.risk_score <= max_risk)
    sort_col = {
        "created_at": Scan.created_at,
        "risk_score": Scan.risk_score,
        "confidence": Scan.confidence,
        "url": Scan.url,
    }.get(sort, Scan.created_at)
    stmt = stmt.order_by(sort_col.desc() if order != "asc" else sort_col.asc())
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return HistoryList(
        items=[
            HistoryItem(
                id=r.id,
                url=r.url,
                classification=r.classification,
                risk_score=r.risk_score,
                confidence=r.confidence,
                threat_level=r.threat_level,
                created_at=r.created_at,
                demo=bool(r.demo),
            )
            for r in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/history/{scan_id}", response_model=AnalyzeResponse)
def history_detail(scan_id: int, db: Session = Depends(get_db)) -> AnalyzeResponse:
    scan = db.scalar(
        select(Scan)
        .options(selectinload(Scan.risk_factors), selectinload(Scan.features))
        .where(Scan.id == scan_id)
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan_to_response(scan)


@router.delete("/history/{scan_id}")
def history_delete(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    db.delete(scan)
    db.commit()
    return {"deleted": True, "id": scan_id}


@router.get("/analytics")
def analytics(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(Scan.id))) or 0
    by_class = dict(
        db.execute(select(Scan.classification, func.count(Scan.id)).group_by(Scan.classification)).all()
    )
    avg_risk = db.scalar(select(func.avg(Scan.risk_score))) or 0
    avg_conf = db.scalar(select(func.avg(Scan.confidence))) or 0
    indicator_rows = db.execute(
        select(RiskFactor.name, func.count(RiskFactor.id))
        .group_by(RiskFactor.name)
        .order_by(func.count(RiskFactor.id).desc())
        .limit(12)
    ).all()
    # scans over time (day buckets)
    rows = db.scalars(select(Scan).order_by(Scan.created_at.asc()).limit(2000)).all()
    buckets: dict[str, dict[str, int]] = {}
    for s in rows:
        day = (s.created_at or datetime.now(timezone.utc)).date().isoformat()
        buckets.setdefault(day, {"legitimate": 0, "suspicious": 0, "phishing": 0, "total": 0})
        buckets[day][s.classification] = buckets[day].get(s.classification, 0) + 1
        buckets[day]["total"] += 1
    risk_hist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s in db.scalars(select(Scan)).all():
        risk_hist[s.threat_level] = risk_hist.get(s.threat_level, 0) + 1
    return {
        "total_scans": total,
        "phishing": by_class.get("phishing", 0),
        "suspicious": by_class.get("suspicious", 0),
        "legitimate": by_class.get("legitimate", 0),
        "average_risk": round(float(avg_risk), 2),
        "average_confidence": round(float(avg_conf), 4),
        "classification_distribution": by_class,
        "risk_distribution": risk_hist,
        "scans_over_time": [{"date": k, **v} for k, v in sorted(buckets.items())],
        "common_indicators": [{"name": n, "count": c} for n, c in indicator_rows],
        "top_ml_features": load_feature_importance()[:12],
    }


@router.get("/model/metrics")
def model_metrics():
    return load_metrics()


@router.get("/model/features")
def model_features():
    return {"features": load_feature_importance()}


@router.get("/report/{scan_id}")
def report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.scalar(
        select(Scan)
        .options(selectinload(Scan.risk_factors), selectinload(Scan.features))
        .where(Scan.id == scan_id)
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    result = scan_to_response(scan)
    lines = [
        "PHISHGUARD AI",
        "Security Analysis Report",
        "",
        f"URL: {result.url}",
        f"Normalized: {result.normalized_url}",
        f"Verdict: {result.classification.upper()}",
        f"Risk: {result.risk_score}/100 ({result.threat_level})",
        f"Confidence: {result.confidence:.0%}",
        f"Timestamp: {result.created_at}",
        f"Demo/test scan: {'yes' if result.demo else 'no'}",
        "",
        "Summary",
        result.summary,
        "",
        "Detected signals",
    ]
    for rf in result.risk_factors:
        lines.append(f"- [{rf.severity.upper()}] {rf.name}: {rf.explanation}")
    lines += ["", "Recommended actions", result.recommendation, "", result.https_note, result.confidence_note]
    text = "\n".join(lines)
    return StreamingResponse(
        io.BytesIO(text.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="phishguard-report-{scan_id}.txt"'},
    )


@router.post("/admin/retrain", dependencies=[Depends(require_admin)])
def admin_retrain():
    raise HTTPException(
        status_code=501,
        detail="Retraining is not exposed in the API process. Run `python ml/training/train.py` on a trusted workstation.",
    )
