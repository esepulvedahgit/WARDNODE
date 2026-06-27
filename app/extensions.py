from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

csrf = CSRFProtect()
db = SQLAlchemy()
limiter = Limiter(
    key_func=get_remote_address,
    in_memory_fallback_enabled=True,
)
login_manager = LoginManager()
migrate = Migrate()
