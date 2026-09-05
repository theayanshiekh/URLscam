"""End-to-end URL analysis pipeline."""

from __future__ import annotations

import json
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.db_models import FeatureRow, RiskFactor, Scan
from app.schemas.scan import AnalyzeResponse, RiskFactorOut, UrlBreakdown
from app.services.explainability import (
    build_summary,
    confidence_note,
    humanize_ml_contributions,
    https_note,
    RECS,
)
from app.services.features import extract_features
from app.services.heuristics import run_heuristics
from app.services.intel import gather_intelligence
from app.services.ml_engine import predict
from app.services.risk_engine import combine_risk
from app.utils.url_parser import parse_url

StageCallback = Callable[[str], None]

STAGES = [
    "Parsing URL",
    "Extracting lexical features",
    "Inspecting domain structure",
    "Checking security signals",
    "Running ML model",
    "Running heuristic engine",
    "Generating explanation",
]


def _breakdown(parsed, features, factors) -> UrlBreakdown:
    suspicious = []
    if parsed.is_ip:
        suspicious.append("hostname")
    if parsed.punycode:
        suspicious.append("hostname")
    if len(parsed.subdomains) >= 3:
        suspicious.append("subdomains")
    if features.get("keyword_groups"):
        suspicious.append("path")
    if any("Brand" in f["name"] or "Typosquat" in f["name"] for f in factors):
        suspicious.append("hostname")
    tld = parsed.tld or ""
    return UrlBreakdown(
        scheme=parsed.scheme,
        username=parsed.username,
        hostname=parsed.hostname,
        port=parsed.port,
        path=parsed.path or "/",
        query=parsed.query or None,
        fragment=parsed.fragment or None,
        registrable_domain=parsed.registrable_domain,
        subdomains=parsed.subdomains,
        tld=tld,
        is_ip=parsed.is_ip,
        punycode=parsed.punycode,
        suspicious_components=sorted(set(suspicious)),
    )


def analyze_url(url: str, db: Session | None = None, demo: bool = False, on_stage: StageCallback | None = None) -> AnalyzeResponse:
    completed: list[str] = []

    def stage(name: str) -> None:
        completed.append(name)
        if on_stage:
            on_stage(name)

    stage("Parsing URL")
    parsed = parse_url(url)

    stage("Extracting lexical features")
    features = extract_features(parsed)
    serializable_features = {
        k: v
        for k, v in features.items()
        if k not in {"character_distribution"} and not isinstance(v, (list, dict))
    }
    serializable_features["keyword_groups"] = features.get("keyword_groups")
    serializable_features["subdomains"] = features.get("subdomains")
    serializable_features["tld"] = features.get("tld")
    serializable_features["registrable_domain"] = features.get("registrable_domain")

    stage("Inspecting domain structure")
    intel = gather_intelligence(parsed)

    stage("Checking security signals")
    # TLS/DNS already collected; heuristics next after ML so UI order matches architecture.

    stage("Running ML model")
    ml = predict(features)

    stage("Running heuristic engine")
    factors, heuristic_score = run_heuristics(parsed, features)
    for note in intel.get("notes") or []:
        factors.append(
            {
                "name": "Infrastructure signal",
                "severity": "medium",
                "score": 6,
                "explanation": note,
                "evidence": "dns/tls/rdap",
                "what_it_means": note,
                "why_it_matters": "Infrastructure context is a weighted signal, never a hard rule.",
                "what_to_do": "Confirm the domain through an independent, trusted channel.",
            }
        )

    scored = combine_risk(ml, heuristic_score, factors, intel)
    classification = scored["classification"]

    stage("Generating explanation")
    summary = build_summary(classification, factors)
    sources = ["Heuristics", "Risk engine"]
    if ml.get("available"):
        sources.insert(0, "ML")
    if intel.get("rdap", {}).get("available") or intel.get("dns", {}).get("available"):
        sources.append("Domain intelligence")
    vt = intel.get("reputation", {}).get("virustotal", {})
    gsb = intel.get("reputation", {}).get("google_safe_browsing", {})
    if vt.get("checked") and vt.get("status") not in {"unavailable", "not_configured"}:
        sources.append("VirusTotal")
    if gsb.get("checked") and gsb.get("status") == "checked":
        sources.append("Google Safe Browsing")

    ml_out = {**ml, "human_contributions": humanize_ml_contributions(ml)}
    breakdown = _breakdown(parsed, features, factors)
    risk_out = [
        RiskFactorOut(
            name=f["name"],
            severity=f["severity"],
            score=f["score"],
            explanation=f["explanation"],
            evidence=f.get("evidence", ""),
            what_it_means=f.get("what_it_means", ""),
            why_it_matters=f.get("why_it_matters", ""),
            what_to_do=f.get("what_to_do", ""),
        )
        for f in sorted(factors, key=lambda x: -abs(x["score"]))
    ]

    response = AnalyzeResponse(
        url=parsed.original,
        normalized_url=parsed.normalized,
        classification=classification,  # type: ignore[arg-type]
        risk_score=scored["risk_score"],
        confidence=scored["confidence"],
        threat_level=scored["threat_level"],  # type: ignore[arg-type]
        summary=summary,
        recommendation=RECS[classification],
        features=serializable_features,
        risk_factors=risk_out,
        url_breakdown=breakdown,
        analysis_sources=sources,
        ml={**ml_out, "risk_components": scored["components"], "low_confidence": scored["low_confidence"]},
        intel=intel,
        https_note=https_note(),
        confidence_note=confidence_note(scored["low_confidence"]),
        demo=demo,
        stages=completed,
    )

    if db is not None:
        scan = Scan(
            url=response.url,
            normalized_url=response.normalized_url,
            classification=response.classification,
            risk_score=response.risk_score,
            confidence=response.confidence,
            threat_level=response.threat_level,
            summary=response.summary,
            recommendation=response.recommendation,
            analysis_sources=json.dumps(response.analysis_sources),
            url_breakdown=response.url_breakdown.model_dump_json(),
            ml_details=json.dumps(response.ml, default=str),
            demo=1 if demo else 0,
        )
        db.add(scan)
        db.flush()
        for rf in response.risk_factors:
            db.add(
                RiskFactor(
                    scan_id=scan.id,
                    name=rf.name,
                    severity=rf.severity,
                    explanation=rf.explanation,
                    contribution=rf.score,
                    what_it_means=rf.what_it_means,
                    why_it_matters=rf.why_it_matters,
                    what_to_do=rf.what_to_do,
                    evidence=rf.evidence,
                )
            )
        for key, value in serializable_features.items():
            db.add(FeatureRow(scan_id=scan.id, feature_name=key, feature_value=json.dumps(value, default=str)))
        db.commit()
        db.refresh(scan)
        response.id = scan.id
        response.created_at = scan.created_at

    return response


def scan_to_response(scan: Scan) -> AnalyzeResponse:
    features = {row.feature_name: json.loads(row.feature_value) for row in scan.features}
    breakdown_raw = json.loads(scan.url_breakdown or "{}")
    ml = json.loads(scan.ml_details or "{}")
    return AnalyzeResponse(
        id=scan.id,
        url=scan.url,
        normalized_url=scan.normalized_url,
        classification=scan.classification,  # type: ignore[arg-type]
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        threat_level=scan.threat_level,  # type: ignore[arg-type]
        summary=scan.summary,
        recommendation=scan.recommendation,
        features=features,
        risk_factors=[
            RiskFactorOut(
                name=rf.name,
                severity=rf.severity,
                score=rf.contribution,
                explanation=rf.explanation,
                evidence=rf.evidence,
                what_it_means=rf.what_it_means,
                why_it_matters=rf.why_it_matters,
                what_to_do=rf.what_to_do,
            )
            for rf in scan.risk_factors
        ],
        url_breakdown=UrlBreakdown(**breakdown_raw),
        analysis_sources=json.loads(scan.analysis_sources or "[]"),
        ml=ml,
        intel={},
        https_note=https_note(),
        confidence_note=confidence_note(bool(ml.get("low_confidence"))),
        demo=bool(scan.demo),
        created_at=scan.created_at,
        stages=STAGES,
    )
