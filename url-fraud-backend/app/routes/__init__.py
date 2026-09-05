"""Route blueprints module."""
from app.routes.api import api_bp
from app.routes.web import web_bp

__all__ = ["api_bp", "web_bp"]
