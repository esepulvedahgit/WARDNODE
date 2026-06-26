import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROXY_CONFIG_DIR = os.getenv("PROXY_CONFIG_DIR", "generated/nginx")
    GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "data/geoip/GeoLite2-Country.mmdb")
    WARDNODE_SECRET_KEY = os.getenv("WARDNODE_SECRET_KEY", "")
    NGINX_CONTAINER_NAME = os.getenv("NGINX_CONTAINER_NAME", "wardnode-proxy")
    WN_CONSOLE_URL = os.getenv("WN_CONSOLE_URL", "http://console:5000")
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Strict"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day;50 per hour")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    LOGIN_RATELIMIT = os.getenv("LOGIN_RATELIMIT", "10 per hour")
    PROPAGATE_EXCEPTIONS = False
    PASSWORD_RESET_TOKEN_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_MINUTES", "30"))
    PASSWORD_RESET_SHOW_TOKEN = os.getenv("PASSWORD_RESET_SHOW_TOKEN", "false").lower() == "true"
    # URL pública de la consola usada para construir los enlaces en correos salientes.
    # Obligatoria en producción (debe ser https://). Si está vacía, no se envían correos de reset.
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()
    # Hosts permitidos en el header Host — rechaza requests con Host no listado (Flask 3.1+).
    # Ej: TRUSTED_HOSTS=wardnode.midominio.com
    _th = os.getenv("TRUSTED_HOSTS", "").strip()
    TRUSTED_HOSTS: list[str] | None = [h.strip() for h in _th.split(",") if h.strip()] or None


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    PASSWORD_RESET_SHOW_TOKEN = False  # nunca exponer el token en prod, ignora el env
    # Defaults to True in production; set SESSION_COOKIE_SECURE=false in .env.prod for HTTP-only testing
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    # Disable SSL-strict CSRF check — avoids false positives when a proxy passes X-Forwarded-Proto:https
    WTF_CSRF_SSL_STRICT = False


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    PASSWORD_RESET_SHOW_TOKEN = True
