"""Rutas del módulo de backup — solo administradores.

El restore por UI exige re-autenticación (contraseña + TOTP si está activo)
y confirmación tipeada: restaurar la DB equivale a un takeover total, una
cookie de sesión robada no debe bastar.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import pyotp
from flask import flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, logout_user

from app.audit.helpers import log_audit
from app.auth.decorators import roles_required
from app.backup import bp
from app.backup.service import (
    BackupError,
    RestoreValidationError,
    backup_dir,
    create_backup,
    list_backups,
    resolve_backup_path,
    restore_backup,
)
from app.extensions import db, limiter
from app.models import ROLE_ADMIN, AppConfig

log = logging.getLogger(__name__)

MAX_RESTORE_UPLOAD = 2 * 1024**3  # 2 GB
_CONFIRM_TEXT = "RESTAURAR"


def _mask(value: str | None) -> str:
    if not value:
        return ""
    return ("*" * max(0, len(value) - 4)) + value[-4:]


def _get_password_masked() -> tuple[str, bool]:
    from app.encryption import EncryptionNotConfigured

    try:
        return _mask(AppConfig.get_secret("backup_zip_password")), True
    except EncryptionNotConfigured:
        return "", False


@bp.get("/")
@roles_required(ROLE_ADMIN)
def index():
    masked_password, encryption_ok = _get_password_masked()
    return render_template(
        "backup/index.html",
        backups=list_backups(),
        masked_password=masked_password,
        encryption_ok=encryption_ok,
        cfg={
            "enabled": AppConfig.get("backup_enabled") == "1",
            "hour": AppConfig.get("backup_hour") or "3",
            "retention": AppConfig.get("backup_retention") or "7",
            "include_tls": (AppConfig.get("backup_include_tls") or "1") == "1",
            "include_host": (AppConfig.get("backup_include_host") or "1") == "1",
            "email_enabled": AppConfig.get("backup_email_enabled") == "1",
            "email_to": AppConfig.get("backup_email_to") or "",
            "email_max_mb": AppConfig.get("backup_email_max_mb") or "20",
            "last_run_at": AppConfig.get("backup_last_run_at") or "",
            "last_status": AppConfig.get("backup_last_status") or "",
        },
    )


@bp.post("/config")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def config_save():
    from app.encryption import EncryptionNotConfigured, encrypt_secret

    section = request.form.get("section", "")
    changed: list[str] = []

    if section == "scheduler":
        AppConfig.set("backup_enabled", "1" if request.form.get("enabled") else "0")
        try:
            hour = max(0, min(23, int(request.form.get("hour", "3"))))
        except ValueError:
            hour = 3
        AppConfig.set("backup_hour", str(hour))
        try:
            retention = max(1, min(90, int(request.form.get("retention", "7"))))
        except ValueError:
            retention = 7
        AppConfig.set("backup_retention", str(retention))
        AppConfig.set("backup_include_tls", "1" if request.form.get("include_tls") else "0")
        AppConfig.set("backup_include_host", "1" if request.form.get("include_host") else "0")
        changed = ["enabled", "hour", "retention", "include_tls", "include_host"]

    elif section == "email":
        AppConfig.set("backup_email_enabled", "1" if request.form.get("email_enabled") else "0")
        AppConfig.set("backup_email_to", request.form.get("email_to", "").strip()[:500])
        try:
            max_mb = max(1, min(100, int(request.form.get("email_max_mb", "20"))))
        except ValueError:
            max_mb = 20
        AppConfig.set("backup_email_max_mb", str(max_mb))
        changed = ["email_enabled", "email_to", "email_max_mb"]

    elif section == "password":
        raw = request.form.get("zip_password", "")
        current_masked, _ = _get_password_masked()
        if raw and raw != current_masked:
            if len(raw) < 12:
                flash("La contraseña del zip debe tener al menos 12 caracteres.", "danger")
                return redirect(url_for("backup.index"))
            try:
                AppConfig.set("backup_zip_password", encrypt_secret(raw), encrypted=True)
                changed = ["zip_password"]
            except EncryptionNotConfigured:
                flash("WARDNODE_SECRET_KEY no configurada; no se pueden guardar secretos.", "danger")
                return redirect(url_for("backup.index"))
    else:
        flash("Sección de configuración desconocida.", "danger")
        return redirect(url_for("backup.index"))

    db.session.commit()
    if changed:
        log_audit("backup.config.update", resource_type="backup",
                  detail={"section": section, "fields_changed": changed})
    flash("Configuración de backups guardada.", "success")
    return redirect(url_for("backup.index"))


@bp.post("/run")
@roles_required(ROLE_ADMIN)
@limiter.limit("2 per minute")
def run_now():
    try:
        result = create_backup(reason="manual")
        flash(f"Backup creado: {result.path.name} "
              f"({result.size_bytes / 1024**2:.1f} MB).", "success")
    except BackupError as exc:
        flash(f"El backup falló: {exc}", "danger")

    if request.headers.get("HX-Request"):
        return render_template("backup/_backup_rows.html", backups=list_backups())
    return redirect(url_for("backup.index"))


@bp.get("/download/<name>")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def download(name):
    try:
        path = resolve_backup_path(name)
    except BackupError:
        flash("Backup no encontrado.", "danger")
        return redirect(url_for("backup.index"))
    log_audit("backup.download", resource_type="backup", resource_name=name)
    return send_file(path, as_attachment=True, download_name=name,
                     mimetype="application/zip")


@bp.post("/delete/<name>")
@roles_required(ROLE_ADMIN)
@limiter.limit("10 per minute")
def delete(name):
    try:
        path = resolve_backup_path(name)
        path.unlink()
        log_audit("backup.delete", resource_type="backup", resource_name=name,
                  severity="warning")
        flash(f"Backup {name} eliminado.", "success")
    except BackupError:
        flash("Backup no encontrado.", "danger")

    if request.headers.get("HX-Request"):
        return render_template("backup/_backup_rows.html", backups=list_backups())
    return redirect(url_for("backup.index"))


def _reauthenticate() -> bool:
    """Re-auth fuerte para el restore: contraseña + TOTP si está activo."""
    password = request.form.get("current_password", "")
    if not password or not current_user.check_password(password):
        return False

    if current_user.totp_enabled:
        from app.encryption import EncryptionNotConfigured, decrypt_secret

        code = request.form.get("totp_code", "").replace(" ", "")
        try:
            secret = decrypt_secret(current_user.totp_secret) if current_user.totp_secret else None
        except EncryptionNotConfigured:
            return False  # sin bypass de 2FA con la clave rotada
        if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
            return False
    return True


@bp.post("/restore")
@roles_required(ROLE_ADMIN)
@limiter.limit("3 per hour")
def restore():
    # 1. Re-autenticación (mensaje genérico: sin oráculo de qué falló).
    if not _reauthenticate():
        log_audit("backup.restore", resource_type="backup", severity="critical",
                  status="failure", detail={"error": "re-auth fallida"})
        flash("Verificación de identidad fallida.", "danger")
        return redirect(url_for("backup.index"))

    # 2. Confirmación tipeada.
    if request.form.get("confirm_text", "") != _CONFIRM_TEXT:
        flash(f'Debes escribir "{_CONFIRM_TEXT}" para confirmar.', "danger")
        return redirect(url_for("backup.index"))

    # 3. Límite de subida antes de leer el stream.
    if request.content_length and request.content_length > MAX_RESTORE_UPLOAD:
        flash("El archivo excede el tamaño máximo permitido (2 GB).", "danger")
        return redirect(url_for("backup.index"))

    upload = request.files.get("backup_file")
    if upload is None or not upload.filename:
        flash("Selecciona un archivo de backup.", "danger")
        return redirect(url_for("backup.index"))

    zip_password = request.form.get("zip_password", "")
    if not zip_password:
        flash("Indica la contraseña del zip.", "danger")
        return redirect(url_for("backup.index"))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tmp_path = backup_dir() / f"restore-upload-{ts}.zip.part"
    try:
        upload.save(tmp_path)
        result = restore_backup(Path(tmp_path), zip_password)
    except RestoreValidationError as exc:
        log_audit("backup.restore", resource_type="backup", severity="critical",
                  status="failure", detail={"error": str(exc)[:300]})
        flash(f"El backup no pasó la validación: {exc}", "danger")
        return redirect(url_for("backup.index"))
    except BackupError as exc:
        log_audit("backup.restore", resource_type="backup", severity="critical",
                  status="failure", detail={"error": str(exc)[:300]})
        flash(f"El restore falló: {exc}", "danger")
        return redirect(url_for("backup.index"))
    finally:
        tmp_path.unlink(missing_ok=True)

    # La DB restaurada reemplaza usuarios y sesiones: cerrar la propia.
    logout_user()
    flash(
        "Restore completado (backup del "
        f"{result['manifest'].get('created_at', '¿?')[:19]}). "
        "Reinicia los contenedores y vuelve a iniciar sesión.",
        "success",
    )
    return redirect(url_for("auth.login"))


@bp.get("/docs")
@roles_required(ROLE_ADMIN)
def docs():
    """Documentación oficial del módulo de Backups."""
    return render_template("backup/docs.html")
