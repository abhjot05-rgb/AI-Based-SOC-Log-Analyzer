"""JSON API used by the dashboard pages (Stages 9-11)."""
import logging
import random
import shutil
import tempfile
import uuid
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from database.db import DatabaseError
from generators import sample_logs as sl
from parser.log_normalizer import ParseError
from services import analytics as analytics_service, queries
from services import reports as reports_service, settings_view
from services.analysis_pipeline import AnalysisError, analyze_upload, delete_upload, process_file
from services.queries import QueryError

log = logging.getLogger("soc.api")
bp = Blueprint("api", __name__, url_prefix="/api")

SAMPLE_KINDS = ("csv", "json", "windows_csv", "linux_auth")
MAX_SAMPLE_EVENTS = 20_000
MAX_SAMPLE_ATTACKS = 10


def _error(message, status, **extra):
    return jsonify(error=message, **extra), status


@bp.errorhandler(QueryError)
def _bad_query(exc):
    return _error(str(exc), 400)


@bp.errorhandler(DatabaseError)
def _database_error(exc):
    log.error("Database error in API: %s", exc)
    return _error("A database error occurred.", 500)


def _upload_folder():
    folder = Path(current_app.config["UPLOAD_FOLDER"])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


# ======================================================================
# Upload and analysis
# ======================================================================
@bp.post("/upload")
def upload():
    file = request.files.get("file")             # may raise 413 if the upload is too large
    if file is None or not file.filename:
        return _error("No file was uploaded. Send it in a form field named 'file'.", 400)

    safe_name = secure_filename(file.filename)
    extension = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    allowed = current_app.config["ALLOWED_EXTENSIONS"]
    if not safe_name or extension not in allowed:
        return _error(f"File type not allowed. Allowed types: {', '.join(sorted(allowed))}.", 400)

    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    path = _upload_folder() / stored_name
    file.save(path)
    if path.stat().st_size == 0:
        path.unlink(missing_ok=True)
        return _error("The uploaded file is empty.", 400)

    try:
        result = process_file(path, original_name=safe_name[:255], stored_name=stored_name)
    except ParseError as exc:
        path.unlink(missing_ok=True)
        return _error(str(exc), 422)
    except RecursionError:
        path.unlink(missing_ok=True)
        return _error("The file is too deeply nested to read.", 422)
    except AnalysisError as exc:                 # the logs are stored; analysis can be retried
        return _error(str(exc), 500, upload_id=exc.upload_id)

    return jsonify(filename=safe_name, upload_id=result["ingest"]["upload_id"],
                   ingest=result["ingest"], analysis=result["analysis"]), 201


def _body_int(body, key, default, low, high):
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise QueryError(f"'{key}' must be a whole number between {low} and {high}")
    return value


@bp.post("/generate-sample")
def generate_sample():
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    events = _body_int(body, "events", 800, 0, MAX_SAMPLE_EVENTS)
    attacks = _body_int(body, "attacks", 1, 1, MAX_SAMPLE_ATTACKS)
    seed = _body_int(body, "seed", random.randint(1, 10_000_000), 0, 2_147_483_647)
    kind = body.get("kind", "csv")
    if kind not in SAMPLE_KINDS:
        raise QueryError(f"'kind' must be one of: {', '.join(SAMPLE_KINDS)}")

    with tempfile.TemporaryDirectory() as tmp:
        generated = sl.generate_all(out_dir=tmp, seed=seed, normal_events=events,
                                    attack_multiplier=attacks)
        source = Path(generated["files"][kind])
        stored_name = f"{uuid.uuid4().hex}_{source.name}"
        destination = _upload_folder() / stored_name
        shutil.copyfile(source, destination)

    try:
        result = process_file(destination, original_name=source.name, stored_name=stored_name)
    except ParseError as exc:
        destination.unlink(missing_ok=True)
        return _error(str(exc), 422)
    except AnalysisError as exc:
        return _error(str(exc), 500, upload_id=exc.upload_id)

    return jsonify(filename=source.name, kind=kind, seed=seed,
                   upload_id=result["ingest"]["upload_id"], injected=generated["injected"],
                   ingest=result["ingest"], analysis=result["analysis"]), 201


@bp.get("/uploads")
def uploads():
    return jsonify(items=queries.list_uploads())


@bp.post("/uploads/<int:upload_id>/analyze")
def reanalyze(upload_id):
    if not queries.upload_exists(upload_id):
        return _error("Upload not found.", 404)
    try:
        return jsonify(analyze_upload(upload_id))
    except AnalysisError as exc:
        return _error(str(exc), 500, upload_id=upload_id)


@bp.delete("/uploads/<int:upload_id>")
def remove_upload(upload_id):
    if not delete_upload(upload_id, current_app.config["UPLOAD_FOLDER"]):
        return _error("Upload not found.", 404)
    return jsonify(deleted=upload_id)


# ======================================================================
# Reading data
# ======================================================================
@bp.get("/stats")
def stats():
    return jsonify(queries.dashboard_stats(queries.optional_upload_id(request.args)))


@bp.get("/filters")
def filters():
    return jsonify(queries.filter_options())


@bp.get("/logs")
def logs():
    return jsonify(queries.search_logs(request.args, current_app.config["LOGS_PER_PAGE"]))


@bp.get("/alerts")
def alerts():
    return jsonify(queries.search_alerts(request.args, current_app.config["ALERTS_PER_PAGE"]))


@bp.get("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    alert = queries.get_alert(alert_id)
    if alert is None:
        return _error("Alert not found.", 404)
    return jsonify(alert)


@bp.route("/alerts/<int:alert_id>/status", methods=["POST", "PATCH"])
def alert_status(alert_id):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "status" not in body:
        return _error('Send JSON like {"status": "Investigating"}.', 400)
    saved = queries.update_alert_status(alert_id, body["status"])   # QueryError -> 400
    if saved is None:
        return _error("Alert not found.", 404)
    return jsonify(id=alert_id, status=saved)

# ======================================================================
# Threats and Analytics pages
# ======================================================================
@bp.get("/threats")
def threats():
    return jsonify(analytics_service.threat_summary(queries.optional_upload_id(request.args)))


@bp.get("/analytics")
def analytics():
    return jsonify(analytics_service.analytics_data(queries.optional_upload_id(request.args)))

# ======================================================================
# Reports and settings
# ======================================================================
def _check_scope():
    """Returns the requested upload id (or None). 400 for a bad id is raised by queries; 404 here."""
    upload_id = queries.optional_upload_id(request.args)
    if upload_id is not None and not queries.upload_exists(upload_id):
        return upload_id, _error("Upload not found.", 404)
    return upload_id, None


def _csv_response(kind, upload_id, stream):
    response = Response(stream, mimetype="text/csv")
    filename = reports_service.export_filename(kind, upload_id)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@bp.get("/export/alerts.csv")
def export_alerts():
    _, problem = _check_scope()
    if problem:
        return problem
    upload_id, stream = reports_service.alerts_export(request.args)      # QueryError -> 400
    return _csv_response("alerts", upload_id, stream)


@bp.get("/export/logs.csv")
def export_logs():
    _, problem = _check_scope()
    if problem:
        return problem
    upload_id, stream = reports_service.logs_export(request.args)
    return _csv_response("logs", upload_id, stream)


@bp.get("/reports/summary")
def summary_json():
    upload_id, problem = _check_scope()
    if problem:
        return problem
    return jsonify(reports_service.build_summary(upload_id))


@bp.get("/settings")
def app_settings():
    return jsonify(settings_view.current_settings())