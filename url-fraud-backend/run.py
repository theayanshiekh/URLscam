"""
run.py
------
Entry point to launch the URL Fraud Detection Backend Server.
Supports both Flask development mode and Waitress production WSGI mode.
"""

import argparse
import os
import sys

# Ensure UTF-8 console output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app import create_app
from app.config import Config

app = create_app(Config)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="URL Fraud Detection Backend Server")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host IP")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)), help="Port")
    parser.add_argument("--prod", action="store_true", help="Run with Waitress production WSGI server")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    is_debug = args.debug or Config.DEBUG
    mode_str = "Production (Waitress)" if args.prod else ("Development (Debug)" if is_debug else "Development (Flask)")

    print("=" * 65)
    print(">> URL Fraud & Phishing Detection Backend Service")
    print(f">> Server URL:  http://{args.host}:{args.port}")
    print(f">> Web UI:      http://{args.host}:{args.port}/")
    print(f">> Healthcheck: http://{args.host}:{args.port}/api/health")
    print(f">> Runner:      {mode_str}")
    print("=" * 65)

    if args.prod:
        try:
            from waitress import serve
            serve(app, host=args.host, port=args.port)
        except ImportError:
            print("Waitress not installed, falling back to standard server.")
            app.run(host=args.host, port=args.port, debug=False)
    else:
        app.run(host=args.host, port=args.port, debug=is_debug)
