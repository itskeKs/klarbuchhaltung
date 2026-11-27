bind = "0.0.0.0:8000"
workers = 1
threads = 4
timeout = 120
forwarded_allow_ips = ""
# Callback query strings can contain authorization codes.
accesslog = None


def post_worker_init(worker):
    start = worker.wsgi.config.get("KLAR_START_SCHEDULER")
    if start:
        start()
