# Read automatically by gunicorn when it starts in this folder. Anything given on the command line wins over this file.
worker_class = "gthread"
threads = 8
keepalive = 5
