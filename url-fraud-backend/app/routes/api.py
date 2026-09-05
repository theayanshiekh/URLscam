"""
api.py
------
RESTful API Blueprint providing routes for URL fraud prediction,
batch analysis, feature inspection, model info, and feedback reporting.
"""

import time
from flask import Blueprint, request, jsonify, current_app
from app.core.extractor import extract_features, url_to_vector, FEATURE_NAMES

api_bp = Blueprint("api", __name__, url_prefix="/api")
START_TIME = time.time()


@api_bp.route("/v1/health", methods=["GET"])
@api_bp.route("/health", methods=["GET"])
def health_check():
    """Healthcheck endpoint returning system uptime and model status."""
    detector = current_app.detector
    return jsonify({
        "status": "healthy",
        "service": "url-fraud-detection-api",
        "version": "1.0.0",
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "model_loaded": detector is not None,
        "model_name": detector.meta.get("model_name") if detector else None,
        "active_threshold": detector.threshold if detector else None,
    }), 200


@api_bp.route("/v1/check-url", methods=["POST"])
@api_bp.route("/check-url", methods=["POST"])
def check_url():
    """
    Analyzes a single URL for phishing/fraud markers.
    Accepts: { "url": "https://...", "include_features": false, "include_explainability": true }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Bad Request",
            "message": "Missing or invalid 'url' in request payload.",
        }), 400

    include_features = bool(data.get("include_features", False))
    include_explainability = bool(data.get("include_explainability", True))

    try:
        detector = current_app.detector
        result = detector.predict(
            url=url,
            include_features=include_features,
            include_explainability=include_explainability,
        )

        # Audit log in database
        if hasattr(current_app, "db") and current_app.db:
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            current_app.db.log_scan(
                url=result["url"],
                is_flagged=result["is_flagged"],
                probability=result["probability"],
                risk_score=result.get("risk_score", 0.0),
                risk_level=result.get("risk_level", "UNKNOWN"),
                ip_address=client_ip,
            )

        return jsonify(result), 200
    except Exception as exc:
        return jsonify({
            "error": "Inference Error",
            "message": str(exc),
        }), 500


@api_bp.route("/v1/check-urls", methods=["POST"])
@api_bp.route("/check-urls", methods=["POST"])
def check_urls():
    """
    Performs high-throughput vectorised batch analysis over multiple URLs.
    Accepts: { "urls": ["https://...", ...], "include_features": false, "include_explainability": true }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls")

    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({
            "error": "Bad Request",
            "message": "Payload must include a non-empty 'urls' array.",
        }), 400

    max_batch = current_app.config.get("MAX_BATCH_SIZE", 500)
    if len(urls) > max_batch:
        return jsonify({
            "error": "Payload Too Large",
            "message": f"Batch size exceeds maximum limit of {max_batch} URLs.",
        }), 413

    include_features = bool(data.get("include_features", False))
    include_explainability = bool(data.get("include_explainability", True))

    try:
        detector = current_app.detector
        batch_result = detector.predict_batch(
            urls=urls,
            include_features=include_features,
            include_explainability=include_explainability,
        )
        return jsonify(batch_result), 200
    except Exception as exc:
        return jsonify({
            "error": "Batch Inference Error",
            "message": str(exc),
        }), 500


@api_bp.route("/v1/extract-features", methods=["POST"])
@api_bp.route("/extract-features", methods=["POST"])
def inspect_features():
    """
    Extracts and returns the raw 24 lexical features for any URL.
    Useful for model transparency, debugging, and data pipelines.
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Bad Request",
            "message": "Missing or invalid 'url' in request payload.",
        }), 400

    features = extract_features(url.strip())
    vector = url_to_vector(url.strip())

    return jsonify({
        "url": url.strip(),
        "feature_count": len(FEATURE_NAMES),
        "features": features,
        "feature_vector": vector,
        "feature_names": FEATURE_NAMES,
    }), 200


@api_bp.route("/v1/model/info", methods=["GET"])
@api_bp.route("/model/info", methods=["GET"])
def model_info():
    """Returns training metrics, threshold, and feature specifications."""
    detector = current_app.detector
    if not detector:
        return jsonify({"error": "Model not initialized"}), 503
    return jsonify(detector.get_metadata()), 200


@api_bp.route("/v1/reports", methods=["POST"])
def submit_report():
    """
    Submits user/analyst feedback on misclassified URLs (false positive or false negative).
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    reported_as = data.get("reported_as", "").strip().upper()
    actual_status = data.get("actual_status", "").strip().upper()
    notes = data.get("notes", "").strip()
    submitted_by = data.get("submitted_by", "anonymous").strip()

    if not url:
        return jsonify({"error": "Bad Request", "message": "Missing 'url' parameter."}), 400
    if reported_as not in ("FALSE_POSITIVE", "FALSE_NEGATIVE", "PHISHING", "CLEAN"):
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid 'reported_as'. Must be FALSE_POSITIVE, FALSE_NEGATIVE, PHISHING, or CLEAN.",
        }), 400

    if hasattr(current_app, "db") and current_app.db:
        report_id = current_app.db.add_report(
            url=url,
            reported_as=reported_as,
            actual_status=actual_status or ("LEGITIMATE" if reported_as == "FALSE_POSITIVE" else "FRAUDULENT"),
            notes=notes,
            submitted_by=submitted_by,
        )
        return jsonify({
            "status": "success",
            "message": "Feedback report recorded successfully.",
            "report_id": report_id,
        }), 201

    return jsonify({"status": "acknowledged", "message": "Feedback received (database logging disabled)."}), 200


@api_bp.route("/v1/reports", methods=["GET"])
def get_reports():
    """Retrieves recent analyst feedback reports."""
    if hasattr(current_app, "db") and current_app.db:
        limit = min(int(request.args.get("limit", 50)), 200)
        reports = current_app.db.get_recent_reports(limit=limit)
        return jsonify({"reports": reports, "count": len(reports)}), 200
    return jsonify({"reports": [], "count": 0}), 200


@api_bp.route("/v1/stats", methods=["GET"])
def get_stats():
    """Returns aggregated audit statistics from the database."""
    if hasattr(current_app, "db") and current_app.db:
        return jsonify(current_app.db.get_scan_stats()), 200
    return jsonify({"total_scans": 0, "total_flagged": 0, "total_clean": 0}), 200
