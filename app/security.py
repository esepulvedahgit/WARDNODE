from urllib.parse import urlsplit

from flask import Flask, current_app, flash, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException


def register_security_controls(app: Flask) -> None:
    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        app.logger.warning("CSRF rechazado: %s", error.description)
        flash("Tu sesión expiró por inactividad. Vuelve a intentarlo.", "warning")
        ref = request.referrer
        if ref:
            parsed = urlsplit(ref)
            if not parsed.netloc or parsed.netloc == request.host:
                return redirect(ref)
        return redirect(url_for("auth.login"))

    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning("400 Bad Request: %s", error)
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return render_template("errors/405.html"), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(error):
        current_app.logger.exception("Unhandled application error")
        return render_template("errors/500.html"), 500

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        code = error.code or 500
        variant = "warning" if code < 500 else "danger"
        app.logger.warning("HTTP %s: %s", code, error.description)
        return render_template(
            "errors/error.html",
            code=code,
            title=error.name,
            desc=error.description,
            icon_variant=variant,
        ), code

