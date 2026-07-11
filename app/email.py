import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app

from app.models import AppConfig
from app.encryption import decrypt_secret


def _smtp_cfg():
    from app.encryption import EncryptionNotConfigured
    host    = AppConfig.get("smtp_host") or ""
    port    = int(AppConfig.get("smtp_port") or 587)
    from_   = AppConfig.get("smtp_from") or ""
    use_tls = (AppConfig.get("smtp_use_tls") or "1") == "1"
    try:
        username = decrypt_secret(AppConfig.get("smtp_username")) or ""
        password = decrypt_secret(AppConfig.get("smtp_password")) or ""
    except EncryptionNotConfigured:
        # WARDNODE_SECRET_KEY rotado — credenciales no descifrables; el envío fallará
        # de forma controlada en lugar de crashear con una excepción no manejada.
        username = ""
        password = ""
    from_ = from_ or username
    return host, port, username, password, from_, use_tls


def smtp_configured() -> bool:
    return bool(AppConfig.get("smtp_host") or "")


def _sanitize_subject(subject: str) -> str:
    # Defensa CRLF (CWE-93): ninguna cabecera puede contener saltos de línea.
    return subject.replace("\r", " ").replace("\n", " ")[:200]


def _send(msg, to_emails: list[str], from_: str, host: str, port: int,
          username: str, password: str, use_tls: bool) -> None:
    with smtplib.SMTP(host, port) as s:
        if use_tls:
            s.starttls()
        if username:
            s.login(username, password)
        s.sendmail(from_, to_emails, msg.as_string())


def send_email(
    to_emails: list[str],
    subject: str,
    body: str,
    *,
    html_body: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> None:
    """Envío genérico con soporte de adjuntos.

    attachments: lista de (filename, payload_bytes, mimetype). Lanza RuntimeError
    si SMTP no está configurado — el caller decide degradar con gracia.
    """
    host, port, username, password, from_, use_tls = _smtp_cfg()
    if not host:
        raise RuntimeError("SMTP no configurado")
    subject = _sanitize_subject(subject)

    if html_body is not None:
        text_part = MIMEMultipart("alternative")
        text_part.attach(MIMEText(body, "plain", "utf-8"))
        text_part.attach(MIMEText(html_body, "html", "utf-8"))
    else:
        text_part = MIMEText(body, "plain", "utf-8")

    if attachments:
        msg = MIMEMultipart("mixed")
        msg.attach(text_part)
        for filename, payload, mimetype in attachments:
            maintype, _, subtype = (mimetype or "application/octet-stream").partition("/")
            part = MIMEApplication(payload, _subtype=subtype or "octet-stream")
            # El filename va solo en Content-Disposition; sanitizar saltos por si acaso
            safe_name = filename.replace("\r", "").replace("\n", "")
            part.add_header("Content-Disposition", "attachment", filename=safe_name)
            msg.attach(part)
    else:
        msg = text_part

    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = ", ".join(to_emails)
    _send(msg, to_emails, from_, host, port, username, password, use_tls)


def send_soc_alert_email(
    to_emails: list[str],
    subject: str,
    body: str,
    *,
    html_body: str | None = None,
) -> None:
    """Alerta SOC por email (wrapper de send_email, firma estable para callers)."""
    send_email(to_emails, subject, body, html_body=html_body)


def send_smtp_test_email(to_email: str) -> None:
    body = (
        "Este es un correo de prueba de WardNode.\n\n"
        "Si lo recibiste, la configuracion SMTP esta funcionando correctamente."
    )
    send_email([to_email], "Prueba de configuracion SMTP — WardNode", body)


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    minutes = current_app.config.get("PASSWORD_RESET_TOKEN_MINUTES", 30)
    body = (
        f"Haz clic en el siguiente enlace para restablecer tu contraseña:\n\n"
        f"{reset_url}\n\n"
        f"Este enlace expira en {minutes} minutos."
    )
    send_email([to_email], "Restablecer contraseña — WardNode", body)
