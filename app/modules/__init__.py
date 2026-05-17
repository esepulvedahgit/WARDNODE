from flask import Blueprint

bp = Blueprint("modules", __name__, url_prefix="/modules")

from app.modules import routes  # noqa: F401, E402
