# AI-Based SOC Log Analyzer & Threat Detection System

A simplified Security Operations Center (SOC) tool. It reads security log files, detects suspicious
activity with configurable rules and an Isolation Forest anomaly detector, scores each finding from
0 to 100, and presents the results in a dark-themed dashboard with alert investigation pages and
exportable reports.

**It only analyzes log files. It never scans, probes, or attacks anything.**

7th-semester B.Tech Computer Science (Cybersecurity) project.

---

## 1. Features

- Upload CSV, JSON, Linux `auth.log`, and Windows-style Security-event CSV logs (max 10 MB)
- Parser and normalizer that handle missing and malformed fields safely
- Six configurable detection rules: brute force, port scan, suspicious login (off-hours and one user
  from many IPs), account activity, privilege activity, suspicious IP behaviour
- Machine learning anomaly detection (Isolation Forest, scikit-learn)
- Transparent 0-100 threat score, mapped to LOW / MEDIUM / HIGH / CRITICAL, with a written
  explanation of why each alert received its severity
- SOC dashboard with statistics, timeline and attack-distribution charts
- Log viewer: search, filters (IP, username, event type, severity, date), sorting, pagination
- Alerts page with filters and status workflow (New, Investigating, Resolved, False Positive)
- Alert investigation page with the original log, reason, recommended steps, and related events
- Threats and Analytics pages
- Reports: alerts CSV, analyzed logs CSV, printable threat summary report
- Sample-log generator (normal and suspicious events) with an answer key
- `doctor.py` health check

## 2. Technology

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Data processing | Pandas, NumPy |
| Machine learning | scikit-learn (Isolation Forest, StandardScaler) |
| Database | SQLite |
| Frontend | HTML5, CSS3, JavaScript, Bootstrap 5.3 |
| Charts | Chart.js 4.4 |

## 3. Pipeline

```
LOG FILE
   |
LOG INGESTION  ->  PARSER  ->  NORMALIZATION          (parser/)
   |
FEATURE EXTRACTION                                    (ml/feature_engineering.py)
   |
   +--> RULE-BASED DETECTION        (detection/)
   +--> ML ANOMALY DETECTION        (ml/)
            |
      THREAT ANALYSIS -> THREAT SCORING -> SEVERITY   (analysis/threat_scoring.py)
            |
      ALERT SYSTEM -> SQLite DATABASE                 (services/analysis_pipeline.py)
            |
      SOC DASHBOARD -> INVESTIGATION -> REPORTS       (routes/, templates/, static/)
```

All results of one analysis are stored in a single database transaction: either everything is saved
or nothing is.

## 4. Installation (Windows)

Requires **Python 3.10 or newer**.

```
cd soc_log_analyzer
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python setup_structure.py
python doctor.py
```

If PowerShell blocks the activation script, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `venv\Scripts\activate` in CMD.

**Optional, for offline use** (recommended before a demo):

```
mkdir static\vendor
Invoke-WebRequest https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css -OutFile static\vendor\bootstrap.min.css
Invoke-WebRequest https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js -OutFile static\vendor\bootstrap.bundle.min.js
Invoke-WebRequest https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.js -OutFile static\vendor\chart.umd.js
```

## 5. Running

```
python app.py
```

Open http://127.0.0.1:5000. The database (`data/soc_analyzer.db`) is created automatically.

| Environment variable | Default | Meaning |
|---|---|---|
| `SOC_HOST` | `127.0.0.1` | Address to listen on (keep it local) |
| `SOC_PORT` | `5000` | Port |
| `SOC_DEBUG` | `0` | Set to `1` for Flask debug mode (development only) |
| `SOC_SECRET_KEY` | random | Flask secret key. Generated at start if not set |

## 6. Using the application

1. **Dashboard**: click **Generate** to create demo logs, or upload your own file. The analysis runs
   immediately.
2. Click a severity card to open the **Alerts** page already filtered.
3. Click an alert ID to open the **investigation page**: reason, why this severity, recommended steps,
   original log, related events. Change the alert status there or in the table.
4. **Logs**: search and filter events. Tick "ML anomalies only" to see what the model flagged.
5. **Threats** and **Analytics**: breakdowns by threat type, attacker, time, and ML result.
6. **Reports**: download the CSVs or open the printable summary (browser Print, then Save as PDF).
7. **Settings**: see the thresholds in use and re-analyze an upload after editing `config.py`.

### Sample logs from the command line

```
python -m generators.sample_logs                       # writes data/samples/
python -m generators.sample_logs --events 3000 --attacks 3 --seed 7
```

## 7. Configuration

All detection thresholds, ML settings, scoring weights, and severity bands are in `config.py`.
Edit the file, restart the app, then use **Settings -> Re-analyze**. Invalid values are reported by
the Settings page and by `python doctor.py`.

| Setting | Where | Meaning |
|---|---|---|
| `DETECTION_RULES` | `config.py` | Thresholds and time windows per rule |
| `ML_SETTINGS` | `config.py` | Isolation Forest settings, minimum events to train |
| `SCORING_SETTINGS` | `config.py` | Point weights for the threat score |
| `SEVERITY_BANDS` | `config.py` | Score ranges for LOW, MEDIUM, HIGH, CRITICAL |

## 8. Detection rules

| Rule | Triggers when |
|---|---|
| Brute force | More than 5 failed logins from one IP within 120 s (also notes a later success) |
| Port scan | More than 15 distinct destination ports from one IP within 60 s |
| Suspicious login | Successful login 22:00-06:00, or one user from more than 3 IPs within 1 h |
| Account activity | At least 3 account events (created, enabled, reset, disabled, locked) within 5 min |
| Privilege activity | At least 2 privilege or group-change events (or sudo) within 5 min |
| Suspicious IP | More than 10 failures or blocks from one IP within 10 min |

(The numbers above are the defaults in `config.py`.)

## 9. Threat score

The score is a sum of whole-number points, capped at 100: threat-type base weight, failed attempts
over the threshold, event frequency, affected accounts, ML anomaly score, source-IP behaviour, and
escalation indicators (for example a successful login after a brute-force attack). Every alert stores
a sentence-by-sentence explanation that adds up to its score.

## 10. Machine learning: what it is and is not

- The model is an **Isolation Forest**, an **unsupervised anomaly detector**. It learns what is
  typical in the analyzed file and flags what stands out.
- It is **not** an attack classifier. There is no labelled training data, so **no accuracy figure is
  claimed anywhere in this project**.
- `contamination` (default 0.05) is the share of events the model flags by design. The "ML
  anomalies" count therefore follows that setting and does not measure how many attacks exist.
- If a file is mostly attack traffic, little will look unusual to the model.
- ML-only alerts are labelled "Anomalous Activity": leads to review, not confirmed attacks.
- The Analytics page shows how many events inside rule alerts the model also flagged. That is
  agreement between two methods, not accuracy.

## 11. Evaluation

The generator records how many attacks it injected. Compare that with the detections:

```
python -m analysis.answer_key_check
```

This compares **counts** per scenario. It does not compute precision or recall, because the answer
key does not say which log rows belong to which attack.

## 12. Testing

```
python -m unittest discover -s tests -t . -v
```

Tests cover each stage, plus an end-to-end journey, bad and oversized files, hostile query strings,
CSV formula injection, and escaping of attacker-controlled text. The browser pages (clicking,
charts) are checked manually, see section 14.

## 13. Security

- Upload allow-list (`csv`, `json`, `log`, `txt`), 10 MB limit, `secure_filename`, random stored names,
  empty or unparseable files rejected and removed
- Parameterized SQL only; sort columns come from fixed whitelists; `%` and `_` in search are escaped
- Log data is escaped before display (`esc()` and Jinja autoescape); a Content-Security-Policy blocks
  scripts from other sources
- CSV exports prefix cells starting with `= + - @` so spreadsheets cannot run them as formulas
- Server errors return a generic message; details go to `data/app.log`
- No hard-coded passwords or API keys; the Settings page never shows the secret key

## 14. Manual test checklist

Dashboard (generate all 4 formats), upload refusals (.exe, empty file), Logs filters and paging,
Alerts filters and status change (reload to confirm), investigation page fields, Threats and
Analytics links, both CSVs in Excel, summary report to PDF, Settings checks, and a narrow window
(sidebar becomes a menu button).

## 15. Project structure

```
soc_log_analyzer/
├── app.py                  Flask app, security headers, error handlers
├── config.py               All settings
├── doctor.py               Health check
├── setup_structure.py      Creates folders
├── requirements.txt
├── analysis/               threat_scoring.py, answer_key_check.py
├── database/               schema.py, db.py
├── detection/              rule_engine.py, brute_force.py, port_scan.py, suspicious_login.py,
│                           account_privilege.py, suspicious_ip.py, common.py
├── generators/             sample_logs.py
├── ml/                     feature_engineering.py, model.py, anomaly_detector.py
├── parser/                 csv_parser.py, json_parser.py, linux_parser.py,
│                           log_normalizer.py, ingest.py
├── routes/                 api.py (JSON API), pages.py (HTML pages)
├── services/               analysis_pipeline.py, queries.py, analytics.py,
│                           reports.py, settings_view.py
├── templates/              base, dashboard, logs, alerts, alert_details, threats,
│                           analytics, reports, settings, report_summary
├── static/                 css/soc.css, js/*.js, vendor/ (optional offline libraries)
├── data/                   Database, uploads, samples, app.log (created at run time)
├── reports/                Reserved for saved reports
├── docs/                   VIVA_QA.md
└── tests/                  One test file per stage
```

## 16. API summary

| Method and path | Purpose |
|---|---|
| `POST /api/upload` | Upload and analyze a log file |
| `POST /api/generate-sample` | Generate and analyze demo logs |
| `GET /api/logs`, `/api/alerts` | Filtered, sorted, paginated lists |
| `GET /api/alerts/<id>` | Alert with related logs |
| `POST /api/alerts/<id>/status` | Change alert status |
| `GET /api/stats`, `/api/threats`, `/api/analytics` | Dashboard and analysis data |
| `GET /api/export/alerts.csv`, `/api/export/logs.csv` | CSV exports |
| `GET /api/reports/summary`, `/reports/summary` | Summary report (JSON and HTML) |
| `GET /api/settings` | Settings in use, with validity check |
| `GET /api/uploads`, `POST /api/uploads/<id>/analyze`, `DELETE /api/uploads/<id>` | Upload management |

## 17. Limitations

- **No authentication.** The `users` table exists but is not used. Intended for local use on
  `127.0.0.1`. Do not expose it to a network.
- **No CSRF protection.**
- **Analysis runs inside the upload request.** A 10 MB file can take several seconds.
- **Rule thresholds and scoring weights are judgement-based**, not learned from labelled data.
- **Unsupervised ML**: flags a configured share of events; no accuracy claim is possible.
- **Per-file analysis.** Each upload is analyzed on its own. Nothing is correlated across uploads,
  and the model is trained fresh on each file (a saved model can be loaded in code but the UI does
  not use it).
- **Generated data is simulated.** Results on real logs will differ and need threshold tuning.
- **Linux logs** carry no network events, so port scans cannot be detected from `auth.log` alone.
- **Time zones**: timestamps without a zone are used as written.
- **IPv4-focused tuning.** IPv6 addresses are accepted but the sample data and ranges are IPv4.
- **SQLite** suits a single user. It is not designed for many concurrent analysts.

## 18. Future work

Login and roles (using the existing `users` table), CSRF protection, background analysis with a task
queue, live log tailing, correlation across uploads and sources, threat-intelligence lookups for IPs
(optional, outside this offline design), a model trained on a clean baseline period and reused,
evaluation on a labelled public dataset, alert notifications, and a PostgreSQL option.

## 19. Troubleshooting

Run `python doctor.py` first. It checks Python, packages, project files, the database layout,
settings, and the port.

| Problem | Fix |
|---|---|
| `no such column: upload_id` | Old database file. Stop the app, delete `data\soc_analyzer.db`, restart |
| `TemplateNotFound` | A template is missing from `templates/`. `doctor.py` names it |
| Charts say "Chart library not loaded" | No internet. Download the offline copies (section 4) |
| Page looks stale after editing JS or CSS | Press Ctrl+F5 |
| Port 5000 in use | `$env:SOC_PORT=5001` then `python app.py` |
| Settings page shows "invalid" | Fix the named value in `config.py`, restart, re-analyze |