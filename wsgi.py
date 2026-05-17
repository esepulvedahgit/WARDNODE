import os

from app import create_app
from app.config import Config, ProductionConfig

app = create_app(
    ProductionConfig if os.getenv("FLASK_ENV") == "production" else Config
)
