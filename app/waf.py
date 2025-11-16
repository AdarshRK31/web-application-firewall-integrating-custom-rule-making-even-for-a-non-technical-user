# app/waf.py
import re
from datetime import datetime
from flask import current_app, jsonify
from .models import Rule, AttackPattern, Log, db

MAX_PAYLOAD_LENGTH = 2000  # truncate long payloads before matching/logging

def _safe_get_request_text(req):
    try:
        body = req.get_data(as_text=True) or ''
    except Exception:
        body = ''
    # truncate long bodies to avoid OOM and very long regex evals
    if len(body) > MAX_PAYLOAD_LENGTH:
        body = body[:MAX_PAYLOAD_LENGTH]
    url = (req.url or '')[:1024]
    headers = " ".join([f"{k}:{v}" for k, v in req.headers.items()])[:2048]
    combined = " ".join([url, headers, body])
    return url, body, combined

def _match(pattern, text, is_regex=False):
    if not pattern:
        return False
    if is_regex:
        try:
            # use search for substring anywhere; ignore case
            return re.search(pattern, text, flags=re.IGNORECASE) is not None
        except re.error:
            # invalid regex -> do not match
            return False
    else:
        # plain substring match (case-insensitive)
        return pattern.lower() in text.lower()

def log_violation(req, reason):
    url, body, _ = _safe_get_request_text(req)
    ip = getattr(req, 'remote_addr', None) or req.headers.get('X-Forwarded-For', '')
    entry = Log(
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ip=ip,
        url=(url + (" payload:" + body[:200] if body else ""))[:1024],
        reason=(reason[:512] if reason else "match")
    )
    db.session.add(entry)
    db.session.commit()

def apply_rules(req):
    """
    Inspect request using DB rules and attack patterns.
    Returns (matched_description_or_obj, action) where action is one of:
    'block', 'allow', 'alert', or None (no match).
    """
    url, body, combined = _safe_get_request_text(req)

    # 1) Check active DB rules
    try:
        rules = Rule.query.filter_by(active=True).all()
    except Exception:
        rules = []

    for r in rules:
        is_regex = (getattr(r, 'pattern_type', 'plain') == 'regex')
        cond = (r.condition or '').strip()
        if not cond:
            continue
        # check URL, body, and headers combined text
        if _match(cond, combined, is_regex=is_regex):
            reason = f"Rule:{r.description}"
            # log violation (regardless of action we log)
            log_violation(req, reason)
            # return the action so caller can block if needed
            return (r, r.action)

    # 2) Check preloaded attack patterns (library)
    try:
        patterns = AttackPattern.query.all()
    except Exception:
        patterns = []

    for p in patterns:
        patt = (p.pattern or '').strip()
        if not patt:
            continue
        # attack patterns are intended as regexes (compiled)
        if _match(patt, combined, is_regex=True):
            reason = f"AttackPattern:{p.name} ({p.category})"
            log_violation(req, reason)
            # default behavior for raw attack patterns: block + log
            return (p, 'block')

    # no matches
    return (None, None)

