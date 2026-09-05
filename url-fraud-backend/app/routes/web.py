"""
web.py
------
Web Blueprint serving the interactive URL Fraud Detection dashboard.
"""

from flask import Blueprint, render_template, current_app

web_bp = Blueprint("web", __name__)


@web_bp.route("/", methods=["GET"])
@web_bp.route("/dashboard", methods=["GET"])
def index():
    """Renders the cyber-security themed URL scanner dashboard."""
    detector = current_app.detector
    meta = detector.get_metadata() if detector else {}
    return render_template("index.html", metadata=meta)
