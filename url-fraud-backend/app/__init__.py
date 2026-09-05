"""
Application Factory for the URL Fraud & Phishing Detection Service.
"""

import logging
from flask import Flask, jsonify, request
from flask_cors import CORS

from app.config import Config
from app.core.detector import URLFraudDetector
from app.database.db import Database


def create_app(config_class=Config):
    """Factory function to build and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure structured logging
    logging.basicConfig(
        level=app.config.get("LOG_LEVEL", "INFO"),
        format="[%(asctime)s] [%(levelname)s] in %(module)s: %(message)s",
    )
    logger = logging.getLogger(__name__)

    # Setup CORS for API access
    cors_origins = app.config.get("CORS_ORIGINS", "*")
    CORS(app, resources={r"/api/*": {"origins": cors_origins}})
    logger.info("CORS enabled for origins: %s", cors_origins)

    # Initialize ML detector engine once at startup
    artifacts_dir = app.config.get("ARTIFACTS_DIR")
    threshold_override = app.config.get("THRESHOLD_OVERRIDE")
    try:
        app.detector = URLFraudDetector(
            artifacts_dir=artifacts_dir,
            threshold_override=threshold_override,
        )
        logger.info("Detector successfully initialized.")
    except Exception as exc:
        logger.error("Failed to load detector artifacts from %s: %s", artifacts_dir, exc)
        app.detector = None

    # Initialize SQLite database
    db_path = app.config.get("DATABASE_PATH")
    try:
        app.db = Database(db_path)
        logger.info("Database initialized at %s", db_path)
    except Exception as exc:
        logger.warning("Failed to initialize database at %s: %s", db_path, exc)
        app.db = None

    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.web import web_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

    # Global error handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad Request", "message": str(e)}), 400
        return e

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not Found", "message": "Resource does not exist."}), 404
        return e

    @app.errorhandler(413)
    def handle_payload_too_large(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Payload Too Large", "message": "The payload exceeds allowed limits."}), 413
        return e

    @app.errorhandler(500)
    def handle_internal_server_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return e

    return app
