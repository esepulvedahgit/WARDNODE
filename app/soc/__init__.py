from flask import Blueprint

bp = Blueprint("soc", __name__, url_prefix="/soc")

from app.soc import routes  # noqa: F401, E402
