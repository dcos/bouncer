#!/bin/bash
set -u

# A note on PATH: python and gunicorn live in /opt/mesosphere/bin
# which is part of the PATH set by /opt/mesosphere/environment.

getvalue () {
    # Extract value for key $1 from JSON file, assume flat structure.
    cat "${BOUNCER_CONFIG_FILE_PATH}" | python -c \
        'import sys, json; print(json.load(sys.stdin)[sys.argv[1]])' \
        $1
}

# Detect internal IP and construct cockroachdb connection URL.
my_ip="$(/opt/mesosphere/bin/detect_ip)"
export SQLALCHEMY_DB_URL="cockroachdb://root@${my_ip}:26257/iam"

# Set bouncer's main directory as CWD, then invoke gunicorn.
cd "${BOUNCER_PACKAGE_PATH}/bouncer"
exec gunicorn --worker-class=sync \
    --workers=$(getvalue GUNICORN_WORKER_PROCESSES) \
    --threads=$(getvalue GUNICORN_THREADS_PER_WORKER) \
    --bind=$(getvalue GUNICORN_BIND_ADDRESS) \
    --timeout=$(getvalue GUNICORN_WORKER_TIMEOUT_SECONDS) \
    --name IAM\ Service \
    --access-logfile - \
    --access-logformat '%({X-Forwarded-For}i)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" (%(L)s s)' \
    --error-logfile - \
    --log-level=info \
    bouncer.app.load:wsgiapp
