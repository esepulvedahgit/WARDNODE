import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PROXY_CONFIG_DIR = os.getenv("PROXY_CONFIG_DIR", "generated/nginx")
    GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "data/geoip/GeoLite2-Country.mmdb")
    WARDNODE_SECRET_KEY = os.getenv("WARDNODE_SECRET_KEY", "")
    NGINX_CONTAINER_NAME = os.getenv("NGINX_CONTAINER_NAME", "wardnode-proxy")
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day;50 per hour")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    PROPAGATE_EXCEPTIONS = False
    PASSWORD_RESET_TOKEN_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_MINUTES", "30"))
    PASSWORD_RESET_SHOW_TOKEN = os.getenv("PASSWORD_RESET_SHOW_TOKEN", "false").lower() == "true"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Defaults to True in production; set SESSION_COOKIE_SECURE=false in .env.prod for HTTP-only testing
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    PASSWORD_RESET_SHOW_TOKEN = True
