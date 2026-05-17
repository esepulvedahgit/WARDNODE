from flask import Blueprint

bp = Blueprint("proxy", __name__, url_prefix="/proxy")

from app.proxy import routes  # noqa: E402,F401
