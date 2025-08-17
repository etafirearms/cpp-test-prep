import multiprocessing, os

bind = "0.0.0.0:" + os.getenv("PORT", "5000")
workers = int(os.getenv("WEB_CONCURRENCY", str(max(2, multiprocessing.cpu_count()))))
threads = 2
timeout = 90
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
