# app/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, send_file, current_app, g, Response
from app.models import db, Rule, Log
from app.detector import simulate_traffic, detect_attack, log_detection, compute_severity, push_alert_to_queue
from sqlalchemy import func
import io
import csv
import time
from datetime import datetime, timedelta
import re
import urllib.parse
import json

bp = Blueprint('routes', __name__)
last_alert_sent = {}
recent_alerts = []  # in-memory cache of alerts for SSE and dashboard

# ---------------------------------------------------
#  WAF MIDDLEWARE
# ---------------------------------------------------
@bp.before_app_request
def waf_middleware():
    """Inspect incoming requests for malicious payloads before routing."""
    try:
        path = request.path
        # Skip safe paths
        if path.startswith(('/static', '/api', '/simulate_attack', '/export_logs')) or path.endswith(('.css', '.js', '.png', '.ico')):
            return
        if getattr(g, "already_checked", False):
            return
        g.already_checked = True

        matched, action, reason = detect_attack(request)
        if matched:
            severity = compute_severity(matched, reason)
            log_detection(request, reason, action, severity)

            ip = request.remote_addr or "Unknown"
            now = time.time()

            alert_data = {
                "ip": ip,
                "reason": reason,
                "action": action,
                "severity": severity,
                "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            }
            recent_alerts.append(alert_data)
            push_alert_to_queue(alert_data)
            if len(recent_alerts) > 50:
                recent_alerts.pop(0)

            g.last_attack = {
                "time": datetime.utcnow().isoformat(),
                "reason": reason,
                "action": action,
                "severity": severity
            }
            current_app.logger.info(f"⚠️ Middleware detected: {reason} (Sev {severity}) -> {action}")

    except Exception as e:
        current_app.logger.debug(f"Middleware skipped due to error: {e}")


# ---------------------------------------------------
#  DASHBOARD
# ---------------------------------------------------
@bp.route('/')
def index():
    rules = Rule.query.order_by(Rule.id.desc()).all()
    logs = Log.query.order_by(Log.id.desc()).limit(15).all()
    total_rules = len(rules)
    total_logs = Log.query.count()
    blocked = Log.query.filter(Log.reason.ilike("%blocked%")).count()
    recent_ips = db.session.query(Log.ip).distinct().count()

    return render_template(
        'dashboard.html',
        rules=rules,
        logs=logs,
        total_rules=total_rules,
        total_logs=total_logs,
        blocked=blocked,
        unique_ips=recent_ips,
        added=request.args.get('added', False),
        error=request.args.get('error', False)
    )


# ---------------------------------------------------
#  ADD RULE
# ---------------------------------------------------
@bp.route('/add_rule', methods=['POST'])
def add_rule():
    description = request.form.get('description', '').strip()
    condition = request.form.get('condition', '').strip()
    action = request.form.get('action', '').strip().lower()
    pattern_type = request.form.get('pattern_type', '').strip().lower()

    if not (description and condition and action):
        return redirect(url_for('routes.index', error="Please fill all fields"))

    if action not in {"block", "allow", "alert"}:
        return redirect(url_for('routes.index', error="Invalid action type"))

    if pattern_type == "regex":
        try:
            re.compile(condition)
        except re.error:
            return redirect(url_for('routes.index', error="Invalid regex pattern"))

    new_rule = Rule(description=description, condition=condition, action=action, pattern_type=pattern_type)
    db.session.add(new_rule)
    db.session.commit()
    return redirect(url_for('routes.index', added='true'))


# ---------------------------------------------------
#  DELETE RULE
# ---------------------------------------------------
@bp.route('/delete_rule/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return redirect(url_for('routes.index'))


# ---------------------------------------------------
#  LOGS API
# ---------------------------------------------------
@bp.route('/api/logs', methods=['GET'])
def get_logs():
    q = request.args.get('q', '', type=str).strip()
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(200, max(5, request.args.get('per_page', 10, type=int)))
    date_from = request.args.get('from', type=str)
    date_to = request.args.get('to', type=str)

    query = Log.query
    if date_from:
        query = query.filter(Log.timestamp >= f"{date_from} 00:00:00")
    if date_to:
        query = query.filter(Log.timestamp <= f"{date_to} 23:59:59")
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Log.ip.ilike(like)) |
            (Log.url.ilike(like)) |
            (Log.reason.ilike(like))
        )

    total = query.count()
    logs = query.order_by(Log.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

    def fmt(ts):
        if ts is None:
            return None
        if isinstance(ts, str):
            return ts
        try:
            return ts.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [
            {"id": l.id, "timestamp": fmt(l.timestamp), "ip": l.ip or "Unknown", "url": l.url or "", "reason": l.reason or "Unknown"}
            for l in logs
        ]
    })


# ---------------------------------------------------
#  LOG STATS
# ---------------------------------------------------
@bp.route('/api/logs/stats', methods=['GET'])
def logs_stats():
    rows = db.session.query(
        Log.reason.label('reason'),
        func.count(Log.reason).label('count')
    ).group_by(Log.reason).order_by(func.count(Log.reason).desc()).limit(10).all()
    return jsonify([{"reason": r[0] or "Unknown", "count": r[1]} for r in rows])


# ---------------------------------------------------
#  TOP IPs
# ---------------------------------------------------
@bp.route('/api/logs/top_ips', methods=['GET'])
def top_ips():
    rows = db.session.query(
        Log.ip.label('ip'),
        func.count(Log.ip).label('count')
    ).group_by(Log.ip).order_by(func.count(Log.ip).desc()).limit(10).all()
    return jsonify([{"ip": r[0] or "Unknown", "count": r[1]} for r in rows])


# ---------------------------------------------------
#  EXPORT LOGS
# ---------------------------------------------------
@bp.route('/export_logs', methods=['GET'])
def export_logs():
    q = request.args.get('q', '', type=str).strip()
    date_from = request.args.get('from', type=str)
    date_to = request.args.get('to', type=str)

    query = Log.query
    if date_from:
        query = query.filter(Log.timestamp >= f"{date_from} 00:00:00")
    if date_to:
        query = query.filter(Log.timestamp <= f"{date_to} 23:59:59")
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Log.ip.ilike(like)) |
            (Log.url.ilike(like)) |
            (Log.reason.ilike(like))
        )

    logs = query.order_by(Log.id.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Timestamp", "IP", "URL", "Reason"])
    for l in logs:
        ts = l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(l.timestamp, datetime) else str(l.timestamp)
        cw.writerow([l.id, ts, l.ip or "Unknown", l.url or "", l.reason or "Unknown"])
    mem = io.BytesIO(si.getvalue().encode('utf-8'))
    mem.seek(0)
    filename = f"waf_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=filename)


# ---------------------------------------------------
#  SIMULATE ATTACK
# ---------------------------------------------------
@bp.route('/simulate_attack', methods=['POST'])
def simulate_attack_route():
    data = request.get_json(silent=True) or {}
    attack_type = data.get("type", "random")
    try:
        added_logs = simulate_traffic(attack_type)
        return jsonify({"status": "success", "attack_type": attack_type, "logs_added": added_logs}), 200
    except Exception as e:
        current_app.logger.exception("simulate_attack error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------
#  LIVE STATUS API
# ---------------------------------------------------
@bp.route('/api/live_status', methods=['GET'])
def live_status():
    last_log = Log.query.order_by(Log.id.desc()).first()
    active_rules = Rule.query.count()
    total_logs = Log.query.count()

    def _fmt(ts):
        if ts is None:
            return None
        if isinstance(ts, str):
            return ts
        try:
            return ts.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    latest = {
        "timestamp": _fmt(getattr(last_log, "timestamp", None) if last_log else None),
        "reason": getattr(last_log, "reason", None) if last_log else None,
        "ip": getattr(last_log, "ip", None) if last_log else None,
    }

    return jsonify({
        "active": True,
        "active_rules": active_rules,
        "total_logs": total_logs,
        "latest": latest
    })


# ---------------------------------------------------
#  RECENT ALERTS API
# ---------------------------------------------------
@bp.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Return the last 10 recent alerts (for dashboard UI)."""
    return jsonify(recent_alerts[-10:])


# ---------------------------------------------------
#  STREAM ALERTS (SSE)
# ---------------------------------------------------
@bp.route('/stream_alerts')
def stream_alerts():
    """Send live alerts to frontend via Server-Sent Events."""
    def event_stream():
        last_index = 0
        while True:
            if len(recent_alerts) > last_index:
                alert = recent_alerts[last_index]
                last_index += 1
                yield f"data: {json.dumps(alert)}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")


# ---------------------------------------------------
#  LOG SUMMARY
# ---------------------------------------------------
@bp.route('/api/logs/summary', methods=['GET'])
def logs_summary():
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    today_count = Log.query.filter(Log.timestamp >= today_start).count()
    week_count = Log.query.filter(Log.timestamp >= week_start).count()
    month_count = Log.query.filter(Log.timestamp >= month_start).count()

    return jsonify({
        "today": today_count,
        "week": week_count,
        "month": month_count
    })


