"""
Helpers de auditoría — log_audit() nunca lanza excepciones
para no interferir con el flujo principal de la aplicación.
"""
import json
import logging

_log = logging.getLogger(__name__)


def log_audit(
    action: str,
    resource_type: str | None = None,
    resource_name: str | None = None,
    detail: dict | None = None,
    severity: str = "info",
    status: str = "success",
    actor_email: str | None = None,
    actor_id: int | None = None,
) -> None:
    """Registra un evento de auditoría en la base de datos.

    Usa un savepoint (BEGIN NESTED) para aislar el INSERT del audit de
    cualquier transacción activa en la sesión principal, de modo que
    nunca commitea cambios pendientes de la ruta llamante.

    Nunca propaga excepciones.
    """
    try:
        from flask import request as _req
        from flask_login import current_user as _cu
        from app.models import AuditLog, db

        ip: str | None = None
        try:
            ip = _req.remote_addr
        except Exception:
            pass

        if actor_email is None:
            try:
                if _cu and _cu.is_authenticated:
                    actor_email = _cu.email
                    actor_id = _cu.id
                else:
                    actor_email = "sistema"
            except Exception:
                actor_email = "sistema"

        entry = AuditLog(
            actor_email=actor_email,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_name=resource_name,
            detail=json.dumps(detail, default=str) if detail else None,
            ip_address=ip,
            severity=severity,
            status=status,
        )

        # begin_nested() crea un SAVEPOINT: el commit interno solo aplica
        # al savepoint, sin afectar la transacción exterior de la ruta.
        # Si la sesión no soporta savepoints (SQLite sin WAL), cae al except.
        try:
            with db.session.begin_nested():
                db.session.add(entry)
            db.session.commit()
        except Exception:
            # Fallback: commit directo (SQLite dev sin savepoints, etc.)
            db.session.rollback()
            db.session.add(entry)
            db.session.commit()

    except Exception as exc:
        _log.warning("log_audit falló silenciosamente [%s/%s]: %s", action, status, exc)
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass
