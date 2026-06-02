import multiprocessing

workers = 2 * multiprocessing.cpu_count() + 1
worker_class = "sync"
timeout = 120
bind = "127.0.0.1:5000"
accesslog = "-"
errorlog = "-"
