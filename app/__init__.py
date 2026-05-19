import base64
import tarfile
import urllib.request
from pathlib import Path

from flask import Flask

from app.audit.routes import bp as audit_bp
from app.auth.routes import bp as auth_bp
from app.config import Config
from app.extensions import csrf, db, limiter, login_manager, migrate
from app.main.routes import bp as main_bp
from app.modules import bp as modules_bp
from app.proxy.routes import bp as proxy_bp
from app.security import register_security_controls


def create_app(config_object: type[Config] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or Config)

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

    @app.context_processor
    def inject_module_states():
        try:
            from app.models import AppConfig
            return {
                "module_wf_enabled": AppConfig.get("module_wf_enabled") == "1",
                "module_cs_enabled": AppConfig.get("module_cs_enabled") == "1",
                "module_obs_enabled": AppConfig.get("module_obs_enabled") == "1",
            }
        except Exception:
            return {"module_wf_enabled": False, "module_cs_enabled": False, "module_obs_enabled": False}

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
        from app.proxy.services import render_nginx_configs

        db_path = Path(app.config["GEOIP_DB_PATH"])
        if db_path.exists():
            size_mb = db_path.stat().st_size // 1_048_576
            print(f"GeoIP DB presente ({size_mb} MB), sin acción.")
            return

        from app.models import AppConfig
        from app.encryption import decrypt_secret, EncryptionNotConfigured

        try:
            enc_id = AppConfig.get("maxmind_account_id")
            enc_key = AppConfig.get("maxmind_license_key")
            account_id = (decrypt_secret(enc_id) or "") if enc_id else ""
            license_key = (decrypt_secret(enc_key) or "") if enc_key else ""
        except EncryptionNotConfigured:
            account_id = ""
            license_key = ""

        if not account_id or not license_key:
            print("Advertencia: credenciales MaxMind no configuradas. Configúralas desde /proxy/settings.")
            return

        db_path.parent.mkdir(parents=True, exist_ok=True)
        url = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
        credentials = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
        print("Descargando GeoLite2-Country desde MaxMind ...")
        tar_path = db_path.parent / "GeoLite2-Country.tar.gz"
        try:
            # MaxMind returns 302 to a Cloudflare R2 presigned URL.
            # Step 1: capture that URL without following the redirect.
            class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers):
                    raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
                http_error_301 = http_error_302
                http_error_303 = http_error_302
                http_error_307 = http_error_302
                http_error_308 = http_error_302

            no_redirect_opener = urllib.request.build_opener(_CaptureRedirect())
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {credentials}"})
            try:
                no_redirect_opener.open(req, timeout=30)
                download_url = url
            except urllib.error.HTTPError as redir_exc:
                if redir_exc.code in (301, 302, 303, 307, 308):
                    download_url = redir_exc.headers.get("Location")
                    if not download_url:
                        raise RuntimeError("MaxMind redirect sin Location header")
                else:
                    raise

            # Step 2: download from presigned URL — no Authorization header needed
            # R2 presigned URLs may contain literal spaces; encode them
            download_url = download_url.replace(" ", "%20")
            with urllib.request.urlopen(download_url, timeout=120) as resp:
                tar_path.write_bytes(resp.read())
            with tarfile.open(tar_path) as tf:
                mmdb_member = next(m for m in tf.getmembers() if m.name.endswith(".mmdb"))
                with tf.extractfile(mmdb_member) as src:
                    db_path.write_bytes(src.read())
            tar_path.unlink()
            size_mb = db_path.stat().st_size // 1_048_576
            print(f"GeoLite2-Country descargada ({size_mb} MB).")
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode(errors="replace")
            except Exception:
                pass
            print(f"Advertencia: MaxMind respondió HTTP {exc.code} {exc.reason}. {body}")
            if tar_path.exists():
                tar_path.unlink()
            return
        except Exception as exc:
            print(f"Advertencia: no se pudo descargar GeoLite2-Country: {exc}")
            if tar_path.exists():
                tar_path.unlink()
            return

        try:
            render_nginx_configs()
            print("Configs nginx regenerados con geoip2.")
        except Exception as exc:
            print(f"Advertencia: no se regeneraron configs: {exc}")

    @login_manager.user_loader
    def load_user(user_id):
        if not user_id.isdigit():
            return None
        return db.session.get(models.User, int(user_id))

    return app
