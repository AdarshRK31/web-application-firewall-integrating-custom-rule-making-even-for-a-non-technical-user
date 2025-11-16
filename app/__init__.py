
# app/__init__.py
import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail  #  NEW: Flask-Mail for admin alerts

# Global SQLAlchemy instance (used across the app)
db = SQLAlchemy()

#  NEW: Global mail instance
mail = Mail()

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # -------------------------------
    # App Configuration
    # -------------------------------
    app.config.from_mapping(
        SECRET_KEY='dev',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'waf.sqlite3'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        #  NEW: Flask-Mail Configuration (use your credentials or env vars)
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.environ.get('ADMIN_EMAIL', 'your_email@gmail.com'),
        MAIL_PASSWORD=os.environ.get('ADMIN_EMAIL_PASSWORD', 'your_app_password'),
        MAIL_DEFAULT_SENDER=('WAF Alert System', os.environ.get('ADMIN_EMAIL', 'your_email@gmail.com'))
    )

    # Ensure instance directory exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize SQLAlchemy
    db.init_app(app)

    #  Initialize Flask-Mail
    mail.init_app(app)

    # Import models AFTER db.init_app()
    from .models import Rule, Log, AttackPattern

    # -------------------------------
    # Create Tables and Seed Attack Patterns
    # -------------------------------
    with app.app_context():
        try:
            db.create_all()
            from .detector import seed_attack_patterns
            inserted = seed_attack_patterns(app)
            if inserted:
                app.logger.info(f" Seeded {inserted} built-in attack patterns.")
            else:
                app.logger.info("Attack patterns already exist — no new seeds added.")
        except Exception as e:
            # If DB schema mismatch, recreate automatically
            app.logger.warning(f" Error creating DB or seeding: {e}")
            db_path = os.path.join(app.instance_path, 'waf.sqlite3')
            if os.path.exists(db_path):
                app.logger.warning("Recreating database due to schema mismatch...")
                os.remove(db_path)
                db.create_all()
                try:
                    inserted = seed_attack_patterns(app)
                    app.logger.info(f" Recreated DB and seeded {inserted} attack patterns.")
                except Exception as ex2:
                    app.logger.error(f"Seeding failed after recreation: {ex2}")

    # -------------------------------
    # Import Detector Logic
    # -------------------------------
    try:
        from .detector import detect_attack, log_detection
    except Exception as ex:
        app.logger.warning(f" Detector unavailable: {ex}")
        detect_attack = None
        log_detection = None

    # -------------------------------
    # WAF Middleware
    # -------------------------------
    @app.before_request
    def waf_inspection():
        """Inspect every request using WAF detection rules."""
        safe_paths = [
            '/', '/dashboard', '/add_rule', '/delete_rule', '/export_logs',
            '/api/logs', '/api/logs/stats', '/api/logs/top_ips', '/simulate_attack',
            '/static/', '/favicon'
        ]
        if any(request.path.startswith(p) for p in safe_paths):
            return None

        if request.method in ['OPTIONS', 'HEAD']:
            return None

        if not detect_attack:
            return None

        try:
            matched, action, reason = detect_attack(request)
        except Exception as e:
            app.logger.warning(f"WAF detection error: {e}")
            return None

        if matched:
            try:
                if log_detection:
                    log_detection(
                        request,
                        reason or "Matched suspicious input",
                        action or "block"
                    )
            except Exception as e:
                app.logger.warning(f"WAF logging error: {e}")

            action_type = (action or "").lower()
            if action_type == "block":
                return jsonify({
                    "status": "blocked",
                    "reason": reason or "Request blocked by WAF"
                }), 403
            elif action_type == "alert":
                app.logger.warning(f" ALERT: {reason}")
            elif action_type == "log":
                app.logger.info(f"🧾 Logged attack attempt: {reason}")

        return None

    # -------------------------------
    # Register Routes
    # -------------------------------
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    app.logger.info(" WAF Flask App Initialized Successfully with Day 15 Mail Alert Config.")
    return app

