"""HTML pages. Data is loaded by JavaScript from the JSON API (routes/api.py)."""
from pathlib import Path

from flask import (Blueprint, current_app, jsonify, make_response, render_template,
                   request, url_for)

from services import queries, reports as reports_service
from services.queries import QueryError

bp = Blueprint("pages", __name__)

NAV_ITEMS = [
    {"key": "dashboard", "label": "Dashboard", "href": "/", "icon": "▦"},
    {"key": "logs", "label": "Logs", "href": "/logs", "icon": "☰"},
    {"key": "alerts", "label": "Alerts", "href": "/alerts", "icon": "⚠"},
    {"key": "threats", "label": "Threats", "href": "/threats", "icon": "☠"},
    {"key": "analytics", "label": "Analytics", "href": "/analytics", "icon": "◔"},
    {"key": "reports", "label": "Reports", "href": "/reports", "icon": "⎙"},
    {"key": "settings", "label": "Settings", "href": "/settings", "icon": "⚙"},
]

# Library files: CDN by default, local copy automatically if it exists in static/vendor/
CDN = {
    "bootstrap_css": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
    "bootstrap_js": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
    "chart_js": "https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.js",
}
LOCAL_NAMES = {
    "bootstrap_css": "bootstrap.min.css",
    "bootstrap_js": "bootstrap.bundle.min.js",
    "chart_js": "chart.umd.js",
}


def vendor_dir():
    return Path(current_app.static_folder) / "vendor"


@bp.app_context_processor
def layout_settings():
    assets = {}
    for key, cdn_url in CDN.items():
        local = vendor_dir() / LOCAL_NAMES[key]
        assets[key] = (url_for("static", filename=f"vendor/{LOCAL_NAMES[key]}")
                       if local.is_file() else cdn_url)
    return {"assets": assets, "nav_items": NAV_ITEMS}


@bp.get("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@bp.get("/logs")
def logs():
    return render_template("logs.html", active="logs")


@bp.get("/alerts")
def alerts():
    return render_template("alerts.html", active="alerts")


@bp.get("/alerts/<int:alert_id>")
def alert_page(alert_id):
    # The page loads the alert through /api/alerts/<id>; an unknown id shows a clear message.
    return render_template("alert_details.html", active="alerts", alert_id=alert_id)


@bp.get("/threats")
def threats():
    return render_template("threats.html", active="threats")


@bp.get("/analytics")
def analytics():
    return render_template("analytics.html", active="analytics")


@bp.get("/reports")
def reports():
    return render_template("reports.html", active="reports")


@bp.get("/reports/summary")
def report_summary():
    """The printable threat summary report. Add ?download=1 to save it as an HTML file."""
    try:
        upload_id = queries.optional_upload_id(request.args)
    except QueryError as exc:
        return jsonify(error=str(exc)), 400
    if upload_id is not None and not queries.upload_exists(upload_id):
        return jsonify(error="Upload not found."), 404

    summary = reports_service.build_summary(upload_id)
    response = make_response(render_template("report_summary.html", r=summary))
    if request.args.get("download") == "1":
        name = reports_service.export_filename("threat_summary", upload_id, "html")
        response.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return response


@bp.get("/settings")
def settings():
    return render_template("settings.html", active="settings")