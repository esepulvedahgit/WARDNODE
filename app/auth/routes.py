import io
from datetime import datetime, timezone

import pyotp
import qrcode
import qrcode.image.svg
from flask import current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from urllib.parse import urlsplit

from app.auth import bp
from app.auth.decorators import roles_required
from app.auth.password_policy import password_errors
from app.auth.services import (
    admin_exists,
    consume_password_reset_token,
    create_password_reset_token,
    create_user,
    find_usable_password_reset_token,
)
from app.audit.helpers import log_audit
from app.extensions import db, limiter
from app.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_READER, ROLES, User


def _safe_redirect_target(target: str | None) -> str | None:
    if not target:
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    return target


def _email_exists(email: str) -> bool:
    return db.session.query(User.id).filter_by(email=email.strip().lower()).first() is not None


@bp.get("/setup")
def setup_admin():
    if admin_exists():
        return redirect(url_for("auth.login"))
    return render_template("auth/setup.html")


@bp.post("/setup")
@limiter.limit("5 per hour")
def create_initial_admin():
    if admin_exists():
        return redirect(url_for("auth.login"))

    password = request.form["password"]
    if password != request.form["password_confirm"]:
        flash("Las contrasenas no coinciden.", "danger")
        return redirect(url_for("auth.setup_admin"))
    if (faltan := password_errors(password)):
        flash("La contraseña no cumple: " + ", ".join(faltan).lower() + ".", "danger")
        return redirect(url_for("auth.setup_admin"))
    if _email_exists(request.form["email"]):
        flash("El correo ya existe.", "danger")
        return redirect(url_for("auth.setup_admin"))

    create_user(
        email=request.form["email"],
        name=request.form["name"],
        password=password,
        role=ROLE_ADMIN,
    )
    flash("Admin inicial creado. Ahora puedes iniciar sesion.", "success")
    return redirect(url_for("auth.login"))


@bp.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("proxy.dashboard"))
    if not admin_exists():
        return redirect(url_for("auth.setup_admin"))
    return render_template("auth/login.html")


@bp.post("/login")
@limiter.limit(lambda: current_app.config["LOGIN_RATELIMIT"])
def login_post():
    if not admin_exists():
        return redirect(url_for("auth.setup_admin"))

    email = request.form["email"].strip().lower()
    user = User.query.filter_by(email=email, is_active=True).first()
    if user is None or not user.check_password(request.form["password"]):
        log_audit("auth.login_fail", resource_type="auth", resource_name=email,
                  severity="warning", status="failure",
                  actor_email=email)
        flash("Credenciales invalidas.", "danger")
        return redirect(url_for("auth.login"))

    if user.totp_enabled:
        session["_mfa_user_id"] = user.id
        session["_mfa_next"] = request.args.get("next")
        return redirect(url_for("auth.mfa_challenge"))

    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    login_user(user)
    log_audit("auth.login", resource_type="auth", resource_name=email,
              actor_email=user.email, actor_id=user.id)
    return redirect(_safe_redirect_target(request.args.get("next")) or url_for("proxy.dashboard"))


@bp.post("/logout")
def logout():
    log_audit("auth.logout", resource_type="auth")
    logout_user()
    flash("Sesion cerrada.", "success")
    return redirect(url_for("auth.login"))


@bp.get("/forgot-password")
def forgot_password():
    if not admin_exists():
        return redirect(url_for("auth.setup_admin"))
    return render_template("auth/forgot_password.html")


@bp.post("/forgot-password")
@limiter.limit("3 per hour")
def forgot_password_post():
    if not admin_exists():
        return redirect(url_for("auth.setup_admin"))

    user = User.query.filter_by(email=request.form["email"].strip().lower(), is_active=True).first()
    reset_url = None
    if user:
        _, raw_token = create_password_reset_token(
            user=user,
            lifetime_minutes=current_app.config["PASSWORD_RESET_TOKEN_MINUTES"],
        )
        base = current_app.config.get("PUBLIC_BASE_URL", "")
        if base:
            token_url = base.rstrip("/") + url_for("auth.reset_password", token=raw_token)
        else:
            token_url = url_for("auth.reset_password", token=raw_token, _external=True)
        if current_app.config["PASSWORD_RESET_SHOW_TOKEN"]:
            reset_url = token_url
        if base:
            try:
                from app.email import send_password_reset_email, smtp_configured
                if smtp_configured():
                    send_password_reset_email(user.email, token_url)
            except Exception:
                pass
        elif not current_app.config["PASSWORD_RESET_SHOW_TOKEN"]:
            current_app.logger.error(
                "PUBLIC_BASE_URL no configurado; no se envía correo de reset"
            )

    log_audit("auth.password_reset_request", resource_type="auth",
              resource_name=request.form["email"].strip().lower(), severity="info")
    flash("Si el correo existe, se enviaran instrucciones de recuperacion.", "success")
    if reset_url:
        # Modo dev/test (PASSWORD_RESET_SHOW_TOKEN=true): mostrar el enlace inline
        return render_template("auth/forgot_password.html", reset_url=reset_url)
    return redirect(url_for("auth.login"))


@bp.get("/reset-password/<token>")
def reset_password(token):
    reset_token = find_usable_password_reset_token(token)
    if reset_token is None:
        flash("El enlace de recuperacion no es valido o expiro.", "danger")
        return redirect(url_for("auth.forgot_password"))
    return render_template("auth/reset_password.html", token=token)


@bp.post("/reset-password/<token>")
@limiter.limit("5 per hour")
def reset_password_post(token):
    reset_token = find_usable_password_reset_token(token)
    if reset_token is None:
        flash("El enlace de recuperacion no es valido o expiro.", "danger")
        return redirect(url_for("auth.forgot_password"))

    password = request.form["password"]
    if password != request.form["password_confirm"]:
        flash("Las contrasenas no coinciden.", "danger")
        return redirect(url_for("auth.reset_password", token=token))
    if (faltan := password_errors(password)):
        flash("La contraseña no cumple: " + ", ".join(faltan).lower() + ".", "danger")
        return redirect(url_for("auth.reset_password", token=token))

    consume_password_reset_token(reset_token, password)
    log_audit("auth.password_reset", resource_type="auth",
              resource_name=reset_token.user.email,
              actor_email=reset_token.user.email, actor_id=reset_token.user.id,
              severity="warning", status="success")
    flash("Contrasena actualizada.", "success")
    return redirect(url_for("auth.login"))


@bp.get("/users")
@roles_required(ROLE_ADMIN)
def users():
    users = User.query.order_by(User.email).all()
    return render_template("auth/users.html", users=users, roles=ROLES)


@bp.post("/users")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per hour")
def create_user_post():
    password = request.form["password"]
    if password != request.form["password_confirm"]:
        flash("Las contrasenas no coinciden.", "danger")
        return redirect(url_for("auth.users"))
    if (faltan := password_errors(password)):
        flash("La contraseña no cumple: " + ", ".join(faltan).lower() + ".", "danger")
        return redirect(url_for("auth.users"))
    if _email_exists(request.form["email"]):
        flash("El correo ya existe.", "danger")
        return redirect(url_for("auth.users"))

    role = request.form["role"]
    if role not in ROLES:
        flash("Rol invalido.", "danger")
        return redirect(url_for("auth.users"))

    new_email = request.form["email"]
    create_user(
        email=new_email,
        name=request.form["name"],
        password=password,
        role=role,
    )
    log_audit("auth.user_create", resource_type="auth", resource_name=new_email,
              detail={"role": role})
    flash("Usuario creado.", "success")
    return redirect(url_for("auth.users"))


@bp.post("/users/<int:user_id>/delete")
@roles_required(ROLE_ADMIN)
@limiter.limit("20 per hour")
def delete_user_post(user_id):
    user = User.query.get_or_404(user_id)
    # Solo se permiten borrar operador y reader (nunca admins — protege contra
    # autoborrado y contra eliminar el último administrador).
    if user.role == ROLE_ADMIN:
        flash("No se pueden eliminar cuentas de administrador.", "danger")
        return redirect(url_for("auth.users"))

    email = user.email
    role = user.role
    try:
        db.session.delete(user)   # cascada ORM: reset_tokens; TOTP va en la misma fila
        db.session.commit()
    except Exception:
        db.session.rollback()
        log_audit("auth.user_delete", resource_type="auth", resource_name=email,
                  severity="error", status="failure", detail={"role": role})
        flash("Error al eliminar el usuario. Inténtalo de nuevo.", "danger")
        return redirect(url_for("auth.users"))
    log_audit("auth.user_delete", resource_type="auth", resource_name=email,
              severity="warning", detail={"role": role})
    flash("Usuario eliminado.", "success")
    return redirect(url_for("auth.users"))


# ── MFA challenge (during login) ─────────────────────────────────────────────

@bp.get("/mfa")
def mfa_challenge():
    if "_mfa_user_id" not in session:
        return redirect(url_for("auth.login"))
    return render_template("auth/mfa_challenge.html")


@bp.post("/mfa")
@limiter.limit("10 per hour")
def mfa_verify():
    user_id = session.get("_mfa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if user is None or not user.is_active or not user.totp_enabled:
        session.pop("_mfa_user_id", None)
        session.pop("_mfa_next", None)
        return redirect(url_for("auth.login"))

    code = request.form.get("code", "").replace(" ", "")
    from app.encryption import decrypt_secret, EncryptionNotConfigured
    try:
        secret = decrypt_secret(user.totp_secret) if user.totp_secret else None
    except EncryptionNotConfigured:
        # WARDNODE_SECRET_KEY rotado — denegar el acceso de forma segura (sin bypass de 2FA).
        secret = None
    if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash("Codigo invalido o expirado.", "danger")
        return render_template("auth/mfa_challenge.html")

    next_url = session.pop("_mfa_next", None)
    session.pop("_mfa_user_id", None)
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    login_user(user)
    log_audit("auth.mfa_ok", resource_type="auth", actor_email=user.email, actor_id=user.id)
    return redirect(_safe_redirect_target(next_url) or url_for("proxy.dashboard"))


# ── Profile & MFA setup ───────────────────────────────────────────────────────

@bp.get("/profile")
@login_required
def profile():
    return render_template("auth/profile.html")


@bp.post("/profile/mfa/setup")
@login_required
@limiter.limit("10 per hour")
def mfa_setup_start():
    secret = pyotp.random_base32()
    session["_totp_pending"] = secret
    return redirect(url_for("auth.mfa_setup_qr"))


@bp.get("/profile/mfa/setup")
@login_required
def mfa_setup_qr():
    secret = session.get("_totp_pending")
    if not secret:
        return redirect(url_for("auth.profile"))

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="WardNode"
    )
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode("utf-8")
    if "?>" in qr_svg:
        qr_svg = qr_svg.split("?>", 1)[1].strip()

    return render_template("auth/mfa_setup.html", qr_svg=qr_svg, secret=secret)


@bp.post("/profile/mfa/enable")
@login_required
@limiter.limit("10 per hour")
def mfa_enable():
    secret = session.get("_totp_pending")
    if not secret:
        flash("Sesion de configuracion expirada. Intenta de nuevo.", "danger")
        return redirect(url_for("auth.profile"))

    code = request.form.get("code", "").replace(" ", "")
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash("Codigo incorrecto. Verifica que el reloj del dispositivo este sincronizado.", "danger")
        return redirect(url_for("auth.mfa_setup_qr"))

    from app.encryption import encrypt_secret
    current_user.totp_secret = encrypt_secret(secret)
    current_user.totp_enabled = True
    db.session.commit()
    session.pop("_totp_pending", None)
    flash("Autenticacion de dos factores activada.", "success")
    return redirect(url_for("auth.profile"))


@bp.post("/profile/mfa/disable")
@login_required
@limiter.limit("5 per hour")
def mfa_disable():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Contrasena incorrecta.", "danger")
        return redirect(url_for("auth.profile"))

    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.commit()
    flash("Autenticacion de dos factores desactivada.", "success")
    return redirect(url_for("auth.profile"))


@bp.get("/docs")
@login_required
def docs():
    """Documentación de usuarios, roles y MFA (accesible a todos los roles)."""
    return render_template("auth/docs.html")
