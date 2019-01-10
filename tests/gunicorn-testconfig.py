# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


import cProfile
import os
import sys
import traceback
from pathlib import Path

"""
Gunicorn configuration module.

Used from within `wsgi_app_fixture_builder()` when invoking gunicorn directly.
The path to this file is provided to gunicorn's --config command line flag.
"""


# The following section contains Gunicorn configuration variables. In the test
# suite the bind port is usually overwritten via command line flag.
bind = '0.0.0.0:8101'

workers = 1
threads = 1
worker_class = 'sync'

errorlog = '-'
accesslog = '-'
access_log_format = \
    '%({X-Forwarded-For}i)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" (%(L)s s)'
loglevel = 'debug'

proc_name = "IAM Service"

backlog = 2048

# Instruct Gunicorn to not reload upon source file modification.
reload = False


# When running in a devkit container the special `/gunicorn_tmp` path is created
# in container with docker run `--tmpfs` mount. As the default `/tmp` is shared
# between containers and is mounted from the host system the tests were failing
# on macOS and Docker for Mac setup.
# See: http://docs.gunicorn.org/en/stable/settings.html#worker-tmp-dir
# See: http://docs.gunicorn.org/en/stable/faq.html#blocking-os-fchmod
gunicorn_tmp_dir = Path('/gunicorn_tmp')
if gunicorn_tmp_dir.exists():
    worker_tmp_dir = str(gunicorn_tmp_dir)


# Note(JP): Custom configuration parameters, controlling worker process
# profiling. Note that Python's cProfile by default only observes the main
# thread, so this is only useful with `threads=1`. The outpath defines the
# path to the file where profiling data (cProfile stats, precisely) should be
# written to. Enabling profiling increases test time by about 20 % on my
# system.
profiling_enabled = False
profiling_outpath = os.path.abspath("gunicorn-testworker.profile")


def post_fork(server, worker):
    """Gunicorn hook, invoked early after worker process creation."""
    if profiling_enabled:
        profiling_init(worker)


def worker_exit(server, worker):
    """Gunicorn hook, invoked right before worker exit.

    Documented with "Called just after a worker has been exited." However,
    according to gunicorn's arbiter.py, this is called within the worker
    process, right before actually exiting
    """
    worker.log.info("Testconfig's worker exit handler invoked.")

    def handler(server, worker):
        if profiling_enabled:
            profiling_shutdown(worker)

    # Catch all exceptions in handler, and emit information. If we don't do
    # that, gunicorn would swallow the debug information.
    # https://github.com/benoitc/gunicorn/issues/1253
    try:
        handler(server, worker)
    except Exception:
        print("Exception in exit handler:")
        traceback.print_exc(file=sys.stdout)
    worker.log.info("Testconfig's worker exit handler is about to return.")


def profiling_init(worker):
    worker.log.info("Enable profiling in worker process %s" % os.getpid())
    if os.path.exists(profiling_outpath):
        os.remove(profiling_outpath)
    pr = cProfile.Profile()
    pr.enable()
    worker._profiler = pr


def profiling_shutdown(worker):
    worker.log.info("Write profiling data to: %s", profiling_outpath)
    worker._profiler.disable()
    worker._profiler.create_stats()
    worker._profiler.dump_stats(profiling_outpath)
