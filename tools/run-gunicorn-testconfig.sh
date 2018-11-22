#!/bin/bash

# Note(JP): as of today the Bouncer unit tests do not
# test against SQLite, but against CockroachDB. That is,
# passing CI is not a guarantee that `TestConfigSQLite`
# actually works.

export BOUNCER_CONFIG_CLASS="TestConfigSQLite"
export SECRET_KEY_FILE_PATH="/tmp/bouncer-secret-key"

# Configuration values specified on the commandline take
# precedence over values specified in the config file.

# The current database bootstrapping method combined with
# the SQLite in-memory database requires the number of
# threads to be set to 1 so that requests are handled in
# the main thread of the CPython interpreter that runs
# the gunicorn worker process. For background see
# https://gehrcke.de/2015/05/in-memory-sqlite-database-and-flask-a-threading-trap/
exec gunicorn --config tests/gunicorn-testconfig.py \
    --threads=1 --reload bouncer.app.load:wsgiapp
