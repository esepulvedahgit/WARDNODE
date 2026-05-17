import smtplib
from email.mime.text import MIMEText

from flask import current_app

from app.models import AppConfig
from app.encryption import decrypt_secret


def _smtp_cfg():
    host     = AppConfig.get("smtp_host") or ""
    port     = int(AppConfig.get("smtp_port") or 587)
    username = decrypt_secret(AppConfig.get("smtp_username")) or ""
    password = decrypt_secret(AppConfig.get("smtp_password")) or ""
    from_    = AppConfig.get("smtp_from") or username
    use_tls  = (AppConfig.get("smtp_use_tls") or "1") == "1"
    return host, port, username, password, from_, use_tls


def smtp_configured() -> bool:
    return bool(AppConfig.get("smtp_host") or "")


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
