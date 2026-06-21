import multiprocessing
import os

workers = 2 * multiprocessing.cpu_count() + 1
worker_class = "sync"
timeout = 120
bind = os.getenv("GUNICORN_BIND", "0.0.0.0:5000")
accesslog = "-"
errorlog = "-"
