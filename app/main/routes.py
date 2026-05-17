from flask import redirect, render_template, url_for
from flask_login import current_user

from app.main import bp
from app.auth.services import admin_exists


@bp.get("/")
def index():
    if not admin_exists():
        return redirect(url_for("auth.setup_admin"))
    if current_user.is_authenticated:
        return redirect(url_for("proxy.dashboard"))
    return redirect(url_for("auth.login"))


@bp.get("/status")
def status():
    return render_template("main/index.html")


@bp.get("/partials/status")
def status_partial():
    return render_template("main/_status.html")
