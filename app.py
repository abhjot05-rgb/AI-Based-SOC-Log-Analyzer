"""
SOC Log Analyzer - Flask entry point.
Stage 9: HTML dashboard (pages) + JSON API.
"""
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request

import config
from config import Config
from database.db import init_db, list_tables
from routes.api import bp as api_bp
from routes.pages import bp as pages_bp

# Only our own files, plus the two library files from the jsDelivr CDN (Bootstrap, Chart.js).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def setup_logging():
    """Log to console and to data/app.log (rotating, so it can't grow forever)."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    root = logging.getLogger()
    if root.handlers:  # avoid duplicate handlers (e.g. Flask debug reloader)
        return
    root.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        config.LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)


def ensure_directories():
    """Create runtime folders if they don't exist."""
    for folder in (config.DATA_DIR, config.UPLOAD_DIR, config.REPORTS_DIR):
        folder.mkdir(parents=True, exist_ok=True)


def create_app():
    setup_logging()
    ensure_directories()
    init_db()                                   # creates / migrates the SQLite DB

    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["UPLOAD_FOLDER"] = str(config.UPLOAD_DIR)   # read at call time (tests override it)
    log = logging.getLogger("soc.app")

    app.register_blueprint(api_bp)
    app.register_blueprint(pages_bp)

    @app.route("/health")
    def health():
        return jsonify(
            status="ok",
            app="SOC Log Analyzer",
            max_upload_mb=app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
            database_tables=list_tables(),
        )

    # ---------- Security headers ----------
    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---------- Error handling ----------
    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="Not found"), 404

    @app.errorhandler(405)
    def wrong_method(e):
        return jsonify(error="Method not allowed"), 405

    @app.errorhandler(413)
    def too_large(e):
        return jsonify(error="File too large. Maximum upload size is 10 MB."), 413

    @app.errorhandler(OverflowError)
    def number_too_large(e):
        # e.g. /api/alerts/99999999999999999999: a number SQLite cannot store
        return jsonify(error="A number in the request is too large."), 400

    @app.errorhandler(500)
    def server_error(e):
        log.exception("Unhandled server error")
        return jsonify(error="Internal server error"), 500

    log.info("Application created")
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)