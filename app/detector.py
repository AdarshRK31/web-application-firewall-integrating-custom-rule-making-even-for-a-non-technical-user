# app/detector.py
import re
import time
import json
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from flask import current_app, request, jsonify
from functools import wraps
from .models import Rule, Log, db

# -------------------------
# Builtin attack patterns
# -------------------------
BUILTIN_PATTERNS = [
    {"name": "xss_script", "regex": r"<\s*script\b[^>]*>(.*?)<\s*/\s*script>", "action": "block", "reason": "Reflected/Stored XSS - <script> tag"},
    {"name": "xss_on_event", "regex": r"on\w+\s*=\s*['\"\`].+['\"\`]", "action": "block", "reason": "XSS - on* event handler"},
    {"name": "sql_union_select", "regex": r"(?i)\bunion\b.*\bselect\b", "action": "block", "reason": "SQL Injection - UNION SELECT pattern"},
    {"name": "sql_comment_sqli", "regex": r"(--\s|#\s|/\*.*\*/)", "action": "block", "reason": "SQL Injection - Comment style payload"},
    {"name": "sql_sleep", "regex": r"(?i)sleep\((\s*\d+\s*)\)", "action": "block", "reason": "SQL Injection - Time-based injection"},
    {"name": "lfi_traversal", "regex": r"(\.\./\.\.\/|\.\.\\\.\.\\)", "action": "block", "reason": "LFI/RFI - Directory traversal"},
    {"name": "rce_eval_system", "regex": r"(?i)\b(eval|exec|system|passthru|shell_exec|popen)\b", "action": "block", "reason": "RCE attempt - Dangerous function usage"},
    {"name": "rce_cmd_injection", "regex": r"[;&\|`]\s*\w+", "action": "block", "reason": "Command Injection characters"},
    {"name": "suspicious_file_upload", "regex": r"(?i)\.php$|\.phtml$|\.jsp$|\.jspx$", "action": "block", "reason": "Suspicious file upload (web shell)"},
    {"name": "csrf_token_missing", "regex": r"(?i)csrf|x-csrf-token", "action": "log", "reason": "CSRF token/header detected"},
]

# Precompile regex
for pat in BUILTIN_PATTERNS:
    try:
        pat["_compiled"] = re.compile(pat["regex"], re.IGNORECASE | re.DOTALL)
    except re.error:
        pat["_compiled"] = None


# -------------------------
# Helper: Extract request parts
# -------------------------
def _get_request_text_parts(req) -> Dict[str, str]:
    parts = {"url": "", "path": "", "method": "", "query": "", "body": "", "headers": "", "remote_addr": ""}
    try:
        parts["url"] = getattr(req, "url", "") or ""
        parts["path"] = getattr(req, "path", "") or getattr(req, "full_path", "") or ""
        parts["method"] = getattr(req, "method", "") or ""
        args = getattr(req, "args", {}) or {}
        if hasattr(args, "items"):
            parts["query"] = "&".join([f"{k}={v}" for k, v in args.items()])
        else:
            parts["query"] = str(args)
        parts["body"] = req.get_data(as_text=True) if hasattr(req, "get_data") else getattr(req, "body", "") or ""
        hdrs = dict(getattr(req, "headers", {}) or {})
        parts["headers"] = " ".join([f"{k}:{v}" for k, v in hdrs.items()])
        parts["remote_addr"] = getattr(req, "remote_addr", "") or "unknown"
    except Exception:
        pass
    return parts


# -------------------------
# Severity computation helper
# -------------------------
def compute_severity(match_obj: Optional[Any], reason: Optional[str] = None) -> int:
    base = 50
    try:
        if match_obj and hasattr(match_obj, "pattern_type"):
            ptype = (getattr(match_obj, "pattern_type", "") or "").lower()
            base = 55 if ptype == "plain" else 75
        elif match_obj and isinstance(match_obj, dict):
            base = 80
        reason_l = (reason or "").lower()
        if any(k in reason_l for k in ["rce", "command", "exec", "shell"]):
            base = max(base, 85)
        if any(k in reason_l for k in ["sql", "union", "injection", "sleep"]):
            base = max(base, 80)
        if "xss" in reason_l or "<script" in reason_l:
            base = max(base, 75)
    except Exception:
        base = 50
    return min(100, int(base))


# -------------------------
# Attack Detection Logic
# -------------------------
def detect_attack(req) -> Tuple[Optional[Any], Optional[str], Optional[str]]:
    parts = _get_request_text_parts(req)
    haystack = " ".join([parts.get(k, "") for k in ["url", "path", "query", "body", "headers"]])
    try:
        db_rules = Rule.query.filter_by(active=True).all()
    except Exception:
        db_rules = []

    for r in db_rules:
        cond = (r.condition or "").strip()
        if not cond:
            continue
        ptype = (getattr(r, "pattern_type", "") or "").lower()
        try:
            if ptype == "plain":
                if cond.lower() in haystack.lower():
                    return (r, r.action or "block", f"DB Substring Rule: {r.description or cond}")
            else:
                regex = re.compile(cond, re.IGNORECASE | re.DOTALL)
                if regex.search(haystack):
                    return (r, r.action or "block", f"DB Rule triggered: {r.description or cond}")
        except re.error:
            if cond.lower() in haystack.lower():
                return (r, r.action or "block", f"DB Substring Rule (fallback): {r.description or cond}")
        except Exception:
            continue

    for pat in BUILTIN_PATTERNS:
        c = pat.get("_compiled")
        try:
            if c and c.search(haystack):
                return (pat, pat.get("action", "block"), pat.get("reason"))
            if pat["regex"].lower() in haystack.lower():
                return (pat, pat.get("action", "block"), pat.get("reason"))
        except Exception:
            continue
    return (None, None, None)


# -------------------------
# Correlation Engine
# -------------------------
def correlate_attack(ip: str, reason: str) -> bool:
    try:
        recent_logs = Log.query.filter_by(ip=ip).order_by(Log.id.desc()).limit(6).all()
    except Exception:
        recent_logs = []
    keywords = ["sql", "xss", "rce", "csrf", "lfi", "command", "union"]
    reason_l = (reason or "").lower()
    hits = 0
    for l in recent_logs:
        lr = (l.reason or "").lower()
        for k in keywords:
            if k in lr and k in reason_l:
                hits += 1
                break
    return hits >= 2


# -------------------------
# Alert queue (for SSE streaming)
# -------------------------
_ALERT_QUEUE = []


def push_alert_to_queue(data: dict):
    _ALERT_QUEUE.append((time.time(), data))
    if len(_ALERT_QUEUE) > 200:
        _ALERT_QUEUE.pop(0)


# -------------------------
# Notification System (Email removed)
# -------------------------
_last_alert_times: Dict[str, float] = {}


def notify_admin(subject: str, body: str, ip: str = None):
    """Email notifications disabled for local development."""
    current_app.logger.info(f"[INFO] Skipped email alert -> {subject} | {ip}")
    return


# -------------------------
# Logging & Alerts
# -------------------------
def log_detection(req, reason: str, action: str, severity: Optional[int] = None) -> Log:
    ip = getattr(req, "remote_addr", "0.0.0.0")
    url = getattr(req, "url", "/")
    ts = datetime.utcnow()
    if severity is None:
        m, a, r = detect_attack(req)
        severity = compute_severity(m, reason or r)
    reason_text = f"{reason} (Severity: {severity})"
    entry = Log(timestamp=ts, ip=ip, url=url, reason=reason_text, action=action, severity=severity)
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
    try:
        if correlate_attack(ip, reason):
            severity = min(100, severity + 20)
            current_app.logger.warning(f"[ALERT] Repeated attack from {ip}: {reason} | Sev={severity}")
        threshold = int(current_app.config.get("WAF_ALERT_THRESHOLD", 80))
        if severity >= threshold:
            current_app.logger.info(f"[ALERT] {ip}: {reason} | Sev={severity}")
            push_alert_to_queue({
                "ip": ip,
                "reason": reason,
                "severity": severity,
                "timestamp": ts.strftime('%Y-%m-%d %H:%M:%S')
            })
    except Exception as e:
        current_app.logger.exception(f"log_detection error: {e}")
    return entry


# -------------------------
# WAF Decorator
# -------------------------
def waf_protect(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            match, action, reason = detect_attack(request)
            severity = compute_severity(match, reason)
        except Exception as e:
            current_app.logger.exception("detect_attack error: %s", e)
            return f(*args, **kwargs)
        if match:
            try:
                log_detection(request, reason, action, severity)
            except Exception:
                current_app.logger.exception("log_detection failed")
            if (action or "").lower() == "block":
                return jsonify({
                    "status": "blocked",
                    "message": f"Request blocked by WAF: {reason}",
                    "severity": severity
                }), 403
        return f(*args, **kwargs)
    return wrapper


# -------------------------
# Simulation
# -------------------------
class _FakeRequest:
    def __init__(self, url="/", body="", headers=None, remote_addr="127.0.0.1", method="GET", args=None):
        self.url = url
        self.path = url.split("?", 1)[0]
        self.body = body
        self._headers = headers or {}
        self.remote_addr = remote_addr
        self.method = method
        self.args = args or {}

    def get_data(self, as_text=True):
        return self.body if as_text else (self.body.encode("utf-8") if isinstance(self.body, str) else b"")

    @property
    def headers(self):
        return self._headers


def simulate_traffic(attack_type: str = "random", payload: str = None) -> int:
    samples = [
        {"url": "/search?q=<script>alert(1)</script>", "body": "", "headers": {}, "ip": "10.0.0.100"},
        {"url": "/products?id=1 UNION SELECT username,password FROM users", "body": "", "headers": {}, "ip": "10.0.0.101"},
        {"url": "/download?file=../../etc/passwd", "body": "", "headers": {}, "ip": "10.0.0.102"},
        {"url": "/run?cmd=ls -la; cat /etc/passwd", "body": "", "headers": {}, "ip": "10.0.0.103"},
        {"url": "/upload", "body": "file=malicious.php", "headers": {"Content-Type": "multipart/form-data"}, "ip": "10.0.0.104"},
    ]
    if attack_type.lower() != "random":
        samples = [s for s in samples if attack_type.lower() in s["url"].lower() or attack_type.lower() in (s["body"] or "").lower()] or samples
    if payload:
        samples[0]["body"] = payload
    count = 0
    for s in samples:
        r = _FakeRequest(url=s["url"], body=s["body"], headers=s["headers"], remote_addr=s["ip"])
        try:
            m, a, reason = detect_attack(r)
            sev = compute_severity(m, reason)
            if m:
                log_detection(r, reason, a, sev)
                current_app.logger.info(f"[TEST] Simulated attack: {reason} | Sev={sev}")
                count += 1
        except Exception:
            current_app.logger.exception("simulate_traffic error")
    return count


# -------------------------
# Seed Patterns & Initialization
# -------------------------
def seed_attack_patterns(app=None) -> int:
    try:
        from .models import AttackPattern
    except Exception:
        return 0
    ctx = app.app_context() if app else None
    if ctx:
        ctx.push()
    added = 0
    for pat in BUILTIN_PATTERNS:
        try:
            if not AttackPattern.query.filter_by(name=pat["name"]).first():
                ap = AttackPattern(name=pat["name"], regex=pat["regex"], action=pat["action"], reason=pat["reason"])
                db.session.add(ap)
                db.session.commit()
                added += 1
        except Exception:
            db.session.rollback()
    if ctx:
        ctx.pop()
    return added


def init_detector(app=None):
    try:
        inserted = seed_attack_patterns(app)
        simulated = simulate_traffic()
        try:
            current_app.logger.info(f"[WAF] Detector initialized. Seeded {inserted} patterns, simulated {simulated} logs.")
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Detector initialization failed: {e}")

