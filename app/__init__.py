import base64
import tarfile
import urllib.request
from pathlib import Path

from flask import Flask

from app.audit.routes import bp as audit_bp
from app.auth.routes import bp as auth_bp
from app.backup import bp as backup_bp
from app.config import Config
from app.extensions import csrf, db, limiter, login_manager, migrate
from app.main.routes import bp as main_bp
from app.modules import bp as modules_bp
from app.proxy.routes import bp as proxy_bp
from app.security import register_security_controls
from app.soc import bp as soc_bp


def create_app(config_object: type[Config] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or Config)

    if not app.config.get("DEBUG") and not app.config.get("TESTING"):
        base = app.config.get("PUBLIC_BASE_URL", "")
        if not base or not base.startswith("https://"):
            raise RuntimeError(
                "PUBLIC_BASE_URL debe ser una URL https:// en producción. "
                "Configúrala en .env o en las variables de entorno del contenedor."
            )
        if app.config.get("SECRET_KEY", "") in ("", "dev-secret-key", "change-me"):
            raise RuntimeError(
                "SECRET_KEY debe definirse con un valor aleatorio en producción. "
                "Genera uno con: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

    csrf.init_app(app)
    db.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    migrate.init_app(app, db)
    register_security_controls(app)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(proxy_bp)
    app.register_blueprint(modules_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(backup_bp)

    @app.context_processor
    def inject_module_states():
        try:
            from app.models import AppConfig
            console_site_id = AppConfig.get("console_site_id")
            return {
                "module_wf_enabled":     AppConfig.get("module_wf_enabled")   == "1",
                "module_obs_enabled":    AppConfig.get("module_obs_enabled")  == "1",
                "module_soc_enabled":    AppConfig.get("module_soc_enabled")  == "1",
                "module_ddos_enabled":   AppConfig.get("module_ddos_enabled") == "1",
                "module_backup_enabled": (AppConfig.get("module_backup_enabled") or "1") == "1",
                "syslog_enabled":        AppConfig.get("syslog_enabled")      == "1",
                "console_site_configured": bool(console_site_id and console_site_id.isdigit()),
                "setup_prompt_shown": AppConfig.get("setup_prompt_shown") == "1",
            }
        except Exception:
            return {
                "module_wf_enabled":     False,
                "module_obs_enabled":    False,
                "module_soc_enabled":    False,
                "module_ddos_enabled":   False,
                "module_backup_enabled": False,
                "syslog_enabled":        False,
                "console_site_configured": False,
                "setup_prompt_shown": False,
            }

    from app import models  # noqa: F401
    from app.proxy.services import ensure_default_rule_categories

    @app.cli.command("init-db")
    def init_db_command():
        db.create_all()
        ensure_default_rule_categories()
        print("Database initialized.")

    @app.cli.command("db-setup")
    def db_setup_command():
        """Fresh install: create_all + stamp. Existing DB: run pending migrations."""
        from sqlalchemy import inspect as sa_inspect
        from flask_migrate import stamp, upgrade

        insp = sa_inspect(db.engine)
        if "alembic_version" not in insp.get_table_names():
            db.create_all()
            ensure_default_rule_categories()
            stamp()
            print("Base de datos inicializada y migraciones selladas en head.")
        else:
            upgrade()
            print("Migraciones aplicadas.")

    @app.cli.command("ensure-geoip")
    def ensure_geoip_command():
        """Download GeoLite2-Country DB into the volume if not already present."""
        from app.proxy.geoip import download_geoip_db, geoip_db_status, read_maxmind_credentials
        from app.proxy.services import render_nginx_configs

        db_path_str = app.config["GEOIP_DB_PATH"]
        status = geoip_db_status(db_path_str)
        if status["present"]:
            print(f"GeoIP DB presente ({status['size_mb']} MB), sin acción.")
            return

        account_id, license_key = read_maxmind_credentials()
        if not account_id or not license_key:
            print("Advertencia: credenciales MaxMind no configuradas. Configúralas desde /proxy/settings.")
            return

        print("Descargando GeoLite2-Country desde MaxMind ...")
        ok, msg = download_geoip_db(db_path_str, account_id, license_key)
        if not ok:
            print(f"Advertencia: {msg}")
            return

        print(msg)
        try:
            render_nginx_configs()
            print("Configs nginx regenerados con geoip2.")
        except Exception as exc:
            print(f"Advertencia: no se regeneraron configs: {exc}")

    @app.cli.command("render-configs")
    def render_configs_command():
        """Regenera todos los configs nginx desde la base de datos."""
        import click
        from app.proxy.services import render_nginx_configs
        try:
            files = render_nginx_configs()
            click.echo(f"Configs regenerados: {len(files)} archivo(s).")
        except Exception as exc:
            click.echo(f"Advertencia: no se regeneraron configs: {exc}")

    @login_manager.user_loader
    def load_user(user_id):
        raw, _, token = str(user_id).partition(":")
        if not raw.isdigit():
            return None
        user = db.session.get(models.User, int(raw))
        if user is None or user.session_token != token:
            return None
        return user

    @app.cli.command("reap-reset-tokens")
    def reap_reset_tokens_command():
        """Elimina tokens de recuperación de contraseña usados o expirados."""
        import click
        from app.auth.services import purge_expired_reset_tokens
        n = purge_expired_reset_tokens()
        click.echo(f"{n} token(s) eliminado(s).")

    @app.cli.command("reset-encrypted-secrets")
    def reset_encrypted_secrets_command():
        """Borra secretos cifrados en app_config y restablece 2FA tras rotar WARDNODE_SECRET_KEY."""
        import click
        from app.encryption import reset_encrypted_secrets
        result = reset_encrypted_secrets()
        click.echo(
            f"{result['secrets']} secreto(s) cifrado(s) eliminado(s), "
            f"{result['totp']} 2FA restablecido(s)."
        )

    import click

    @app.cli.command("backup-create")
    def backup_create_command():
        """Genera un backup cifrado completo (DB + TLS + estado WF)."""
        from app.backup.service import BackupError, create_backup

        try:
            result = create_backup(reason="cli")
        except BackupError as exc:
            click.echo(f"ERROR: {exc}", err=True)
            raise SystemExit(1)
        click.echo(f"Backup creado: {result.path}")
        click.echo(f"Tamaño: {result.size_bytes / 1024**2:.1f} MB")
        for component, status in result.components.items():
            click.echo(f"  - {component}: {status}")

    @app.cli.command("backup-restore")
    @click.argument("zip_path")
    @click.option("--yes", is_flag=True, help="Omitir la confirmación interactiva.")
    @click.option("--skip-db", is_flag=True, help="Validar y extraer sin restaurar la DB.")
    def backup_restore_command(zip_path, yes, skip_db):
        """Restaura la base de datos desde un backup cifrado. DESTRUCTIVO."""
        from pathlib import Path as _Path

        from app.backup.service import (
            BackupError,
            RestoreValidationError,
            restore_backup,
            validate_backup_zip,
        )

        path = _Path(zip_path)
        if not path.is_file():
            click.echo(f"ERROR: no existe {zip_path}", err=True)
            raise SystemExit(1)

        password = click.prompt("Contraseña del zip", hide_input=True)
        try:
            info = validate_backup_zip(path, password)
        except RestoreValidationError as exc:
            click.echo(f"ERROR de validación: {exc}", err=True)
            raise SystemExit(1)

        manifest = info["manifest"]
        click.echo(f"Backup del: {manifest.get('created_at')}")
        click.echo(f"Motor DB: {manifest.get('db_engine')} · "
                   f"Migración: {manifest.get('alembic_head')}")
        for component, status in (manifest.get("components") or {}).items():
            click.echo(f"  - {component}: {status}")
        if info.get("needs_upgrade"):
            click.echo("Nota: se aplicarán migraciones pendientes tras el restore.")
        if info.get("pg_version_warning"):
            click.echo(f"ADVERTENCIA: {info['pg_version_warning']}")

        if not yes:
            click.confirm(
                "Esto DESTRUYE la base de datos actual y la reemplaza por el backup. ¿Continuar?",
                abort=True,
            )
        try:
            result = restore_backup(path, password, skip_db=skip_db)
        except BackupError as exc:
            click.echo(f"ERROR: {exc}", err=True)
            raise SystemExit(1)
        click.echo("Restore completado.")
        if result["migrations_applied"]:
            click.echo("Migraciones pendientes aplicadas.")
        click.echo("Reinicia los contenedores: docker compose restart console proxy")

    @app.cli.command("backup-prune")
    @click.option("--keep", default=None, type=int, help="Backups a conservar (default: config).")
    def backup_prune_command(keep):
        """Elimina backups antiguos según la política de retención."""
        from app.backup.service import prune_backups
        from app.models import AppConfig

        if keep is None:
            try:
                keep = int(AppConfig.get("backup_retention") or 7)
            except (TypeError, ValueError):
                keep = 7
        removed = prune_backups(keep)
        click.echo(f"{len(removed)} backup(s) eliminado(s)." +
                   (f" ({', '.join(removed)})" if removed else ""))

    from app.proxy.ingest import start_ingest_thread
    start_ingest_thread(app)

    from app.soc.worker import start_soc_thread
    start_soc_thread(app)

    from app.ddos.ingest import start_ddos_ingest_thread
    start_ddos_ingest_thread(app)

    from app.backup.worker import start_backup_thread
    start_backup_thread(app)

    from app.modules.port_monitor import start_port_monitor_thread
    start_port_monitor_thread(app)

    return app
