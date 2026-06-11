import smtplib
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


def send_soc_alert_email(
    to_emails: list[str],
    subject: str,
    body: str,
    *,
    html_body: str | None = None,
) -> None:
    """Alerta SOC por email (mismo patrón SMTP que el reset de contraseña).

    Si html_body se proporciona, envía un mensaje multipart/alternative con
    parte text/plain (fallback) y parte text/html. Los callers existentes que
    no pasan html_body no se ven afectados (parámetro opcional).

    Lanza RuntimeError si SMTP no está configurado — el caller (soc/alerts.py)
    decide degradar con gracia.
    """
    host, port, username, password, from_, use_tls = _smtp_cfg()
    if not host:
        raise RuntimeError("SMTP no configurado")
    # Defensa CRLF (CWE-93): el asunto puede interpolar datos atacante-controlados
    # (source_ip, domain del incidente) — ninguna cabecera puede contener saltos.
    subject = subject.replace("\r", " ").replace("\n", " ")[:200]

    if html_body is not None:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    else:
        msg = MIMEText(body, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = ", ".join(to_emails)
    with smtplib.SMTP(host, port) as s:
        if use_tls:
            s.starttls()
        if username:
            s.login(username, password)
        s.sendmail(from_, to_emails, msg.as_string())


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    host, port, username, password, from_, use_tls = _smtp_cfg()
    if not host:
        raise RuntimeError("SMTP no configurado")
    minutes = current_app.config.get("PASSWORD_RESET_TOKEN_MINUTES", 30)
    body = (
        f"Haz clic en el siguiente enlace para restablecer tu contraseña:\n\n"
        f"{reset_url}\n\n"
        f"Este enlace expira en {minutes} minutos."
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "Restablecer contraseña — WardNode"
    msg["From"]    = from_
    msg["To"]      = to_email
    with smtplib.SMTP(host, port) as s:
        if use_tls:
            s.starttls()
        if username:
            s.login(username, password)
        s.sendmail(from_, [to_email], msg.as_string())
