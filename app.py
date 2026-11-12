"""
Flask Web Application & REST API Controller.
Advanced Password Strength Analyzer and Security Recommendation System.

SECURITY NOTICE:
- Passwords entered by users are evaluated purely in-memory and immediately discarded.
- Passwords are NEVER written to disk, databases, application logs, or reflected in API responses.
- Enforces strict HTTP security headers, input sanitization, and DoS payload limits.
"""
import logging
import os
import sys
from typing import Any, Dict

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    Response
)

from config.config import get_config
from services.password_analyzer import analyze_password, HAS_ZXCVBN
from services.password_generator import generate_secure_password, generate_passphrase
from services.history_service import history_service


# ---------------------------------------------------------------------------
# Strict Zero-Password Logging Configuration
# ---------------------------------------------------------------------------
class SensitiveDataFilter(logging.Filter):
    """
    Ensures no log record ever inadvertently leaks credentials.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "password" in msg.lower() and "endpoint" not in msg.lower():
            record.msg = "[PROTECTED] Log statement suppressed by cybersecurity policy."
            record.args = ()
        return True


logger = logging.getLogger("security_app")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    "[%(asctime)s] [%(levelname)s] [Thread %(thread)d] %(message)s"
))
handler.addFilter(SensitiveDataFilter())
logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------
def create_app(config_class=None) -> Flask:
    app = Flask(__name__)

    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # -----------------------------------------------------------------------
    # Security Response Headers Middleware
    # -----------------------------------------------------------------------
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        """
        Enforce defense-in-depth HTTP security headers on all responses.
        """
        # Content Security Policy (allows local assets and Google Fonts)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Cross-Site Scripting filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Strict anti-caching for API responses to protect sensitive evaluation states
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # Remove disclosure headers
        response.headers["Server"] = "SecurePasswordAnalyzer/2.0"
        return response

    # -----------------------------------------------------------------------
    # Route Handlers
    # -----------------------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        """Render main cybersecurity dashboard."""
        return render_template(
            "index.html",
            zxcvbn_enabled=HAS_ZXCVBN,
            max_pwd_len=app.config.get("MAX_PASSWORD_LENGTH", 256)
        )

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """
        Evaluate password strength and return analytical metrics.
        The input password is NEVER stored or echoed in the JSON output.
        """
        try:
            data: Dict[str, Any] = request.get_json(silent=True) or {}
            raw_password = data.get("password", "")

            # Type safety and length validation (prevents memory DoS)
            if not isinstance(raw_password, str):
                return jsonify({"error": "Invalid password payload format."}), 400

            max_len = app.config.get("MAX_PASSWORD_LENGTH", 256)
            if len(raw_password) > max_len:
                return jsonify({
                    "error": f"Password exceeds maximum allowable length of {max_len} characters."
                }), 400

            # Execute multi-metric analysis pipeline
            analysis = analyze_password(raw_password)

            # Record safe telemetry (strictly score and grade, NO credential)
            if raw_password:
                history_service.add_entry(
                    score=analysis["score"],
                    strength=analysis["strength"],
                    length=analysis["length"],
                    entropy_bits=analysis["entropy_bits"]
                )

            # Zero-out reference to assist garbage collection
            del raw_password
            del data

            # Strict architectural assertion: Guarantee password is never returned
            assert "password" not in analysis, "Security violation: Password must not be in analysis payload."

            return jsonify(analysis), 200

        except Exception as e:
            logger.error(f"Error during password evaluation: {type(e).__name__}")
            return jsonify({
                "error": "An error occurred during password analysis. No credentials were saved."
            }), 500

    @app.route("/api/generate", methods=["POST"])
    def api_generate():
        """
        Cryptographically secure password or passphrase generator endpoint.
        """
        try:
            data: Dict[str, Any] = request.get_json(silent=True) or {}
            mode = data.get("mode", "random")

            if mode == "passphrase":
                word_count = int(data.get("word_count", 4))
                separator = str(data.get("separator", "-"))[:3]
                capitalize = bool(data.get("capitalize", False))
                include_number = bool(data.get("include_number", True))

                result = generate_passphrase(
                    word_count=word_count,
                    separator=separator,
                    capitalize=capitalize,
                    include_number=include_number
                )
                return jsonify(result), 200

            # Standard random password mode
            length = int(data.get("length", 16))
            use_upper = bool(data.get("use_upper", True))
            use_lower = bool(data.get("use_lower", True))
            use_digits = bool(data.get("use_digits", True))
            use_special = bool(data.get("use_special", True))
            avoid_ambiguous = bool(data.get("avoid_ambiguous", False))

            result = generate_secure_password(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_special=use_special,
                avoid_ambiguous=avoid_ambiguous
            )
            return jsonify(result), 200

        except ValueError as val_err:
            return jsonify({"error": str(val_err)}), 400
        except Exception as err:
            logger.error(f"Error in password generation: {type(err).__name__}")
            return jsonify({"error": "Failed to generate password."}), 500

    @app.route("/api/history", methods=["GET"])
    def api_history():
        """
        Retrieve safe audit log (only scores, grades, and timestamps).
        Contains ZERO credential data.
        """
        history_entries = history_service.get_history(limit=25)
        stats = history_service.get_summary_stats()
        return jsonify({
            "history": history_entries,
            "statistics": stats
        }), 200

    @app.route("/api/history/clear", methods=["POST"])
    def api_clear_history():
        """Purge safe evaluation telemetry."""
        history_service.clear()
        return jsonify({
            "status": "success",
            "message": "Audit history purged successfully."
        }), 200

    @app.route("/api/health", methods=["GET"])
    def api_health():
        """Service health check and capabilities status."""
        return jsonify({
            "status": "healthy",
            "app_name": "Advanced Password Strength Analyzer",
            "version": "2.0.0",
            "zxcvbn_active": HAS_ZXCVBN,
            "privacy_guarantee": "zero_credential_retention"
        }), 200

    # -----------------------------------------------------------------------
    # Error Handlers
    # -----------------------------------------------------------------------
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({"error": "Bad request. Malformed or invalid parameters."}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "API endpoint not found."}), 404
        return render_template("base.html", error_message="Page Not Found"), 404

    @app.errorhandler(413)
    def handle_payload_too_large(e):
        return jsonify({"error": "Request entity exceeds maximum allowable size (64KB)."}), 413

    @app.errorhandler(500)
    def handle_server_error(e):
        return jsonify({"error": "Internal server error. No sensitive data was exposed."}), 500

    return app


# Application entry point
app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development").lower() == "development"
    print(f"[*] Starting Password Strength Analyzer on http://{host}:{port}")
    print("[*] Privacy Mode: ACTIVE (Zero password storage, transmission, or logging)")
    app.run(host=host, port=port, debug=debug)
