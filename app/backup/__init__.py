from flask import Blueprint

bp = Blueprint("backup", __name__, url_prefix="/backup")

from app.backup import routes  # noqa: E402,F401
