# Bouncer (DC/OS IAM Service)

Bouncer provides an HTTP API for managing users as well as for login. "Login" in
this context is the process of exchanging primary credentials (such as service
account credentials) into a DC/OS authentication token which can subsequently
presented to DC/OS components.

## Architectural overview

### WSGI application

Bouncer's HTTP API is provided by a
[WSGI](https://www.python.org/dev/peps/pep-0333/) web application which is built
using the [Falcon](http://falcon.readthedocs.io/) framework. Bouncer is
currently intended to be run within [gunicorn](http://gunicorn.org/) using
the `gthread` worker type (with a fixed-size CPython threadpool for processing
HTTP requests).

### Persistence

Bouncer uses [SQLAlchemy](https://www.sqlalchemy.org/) for persisting data in
and reading data from a relational database.

In a production DC/OS environment Bouncer communicates with
a fault-tolerant and highly available CockroachDB cluster comprised of three or
five machines.

When testing Bouncer via `make test` a single containerized CockroachDB instance
is tested against.

When using `make run` or when using `tools/run-gunicorn-testconfig.sh` for a
local playground environment Bouncer operates against an in-memory SQLite
instance.


### A DC/OS authentication token primer

DC/OS has a decentralized authentication architecture using a concept that is
sometimes called client-side sessions.

In DC/OS, Bouncer is the only entity which signs and emits DC/OS authentication
tokens. A DC/OS authentication token is a JSON Web Token (JWT) of type RS256
signed with the private key of an RSA key pair. Bouncer keeps the private key to
itself and exposes the corresponding public key via its JSON Web Key Set (JWKS)
endpoint. A so-called DC/OS authenticator can consume this endpoint and perform
authentication token validation.


## Local development

### The canonical way to run tests

The following command runs the complete test suite just like the Jenkins CI
does and therefore is the canonical way to run tests locally:

    make test

This executes the test runner in a container, and spawns periphery containers
such as for CockroachDB. Upon the first invocation this takes a while for
downloading resources and for building the required container images.


### A more custom way to invoke tests

This is the recommended way for custom invocation of the pytest test runner:

    make shell
    pytest <options>

This is for example useful for executing just a subset of the tests and allows
for quicker iteration than using the `make test` approach.


### Containerized local playground deployment

For a local playground deployment of Bouncer one can launch `make run`. This
starts just a single container in which Bouncer runs against an in-memory SQLite
instance. That is, this deployment model differs significantly from the
production environment in which Bouncer uses CockroachDB.

After the container has come up, test Bouncer's reachability with
`$ curl 127.0.0.1:8101/acs/api/v1/users`

The expected HTTP response status code is 200 with a JSON document in the
response body (the users collection is initially empty, so the JSON document
looks like `{"array": []})`.

Note: For macOS users we recommend running in a Linux virtual machine. We
provide a simple Vagrantfile to use:

```
# Install vagrant:
#   https://www.vagrantup.com/downloads.html

# cd to the Bouncer repository
vagrant up
vagrant ssh
cd /vagrant
make run
```

### Non-containerized local deployment

If you are brave and up for installing various dependencies into your local
development environment then what follows is the way to run Bouncer natively on
your machine:

Install library and header file dependencies:

    # Debian-based systems
    sudo apt-get install nmap \
        libxml2 libxml2-dev \
        libxmlsec1 libxmlsec1-dev \
        libxmlsec1-openssl libxmlsec1-openssl-dev

    # RHEL/Fedora:
    sudo dnf install nmap-ncat \
      libxml2 libxml2-devel \
      xmlsec1 xmlsec1-devel \
      xmlsec1-openssl xmlsec1-openssl-devel \
      libtool-ltdl-devel

Bouncer is currently tested to run with CPython 3.6.x. For setting up a distinct
Python build and for creating a virtual environment form it, we recommend a
yyuu/pyenv-based workflow:

    # Install pyenv:
    #   https://github.com/yyuu/pyenv#basic-github-checkout
    # Install pyenv-virtualenv:
    #   https://github.com/yyuu/pyenv-virtualenv#installing-as-a-pyenv-plugin

    # Create custom local Python build and create a virtualenv from it.
    pyenv install 3.6.6
    pyenv virtualenv 3.6.6 venv366-bouncer
    pyenv activate venv366-bouncer

    # cd to the Bouncer repository and install dependencies from PyPI.
    pip install -r requirements.txt --upgrade
    pip install -r requirements-tests.txt --upgrade


### Debugging in the context of a test run

Logs from the WSGI server are written to the files
`gunicorn_*.outerr`.

After running tests a coverage report can be found in the directory
`coverage-report-html`.


### Profiling the test runner:

If performance bottlenecks need to be understood in the test runner itself
the following recipe can be helpful:

```
# Write profiling data to file `pytest.profile`:
$ python -m cProfile -o pytest.profile $(which pytest) -m app
[...]

# Analyze profile data in the stats browser
$ python -m pstats pytest.profile
Welcome to the profile statistics browser.
pytest.profile% sort time
pytest.profile% stats 10
[...]
```


## Commit messages

Please make sure that

* commits are squashed into logical units.
* commit messages have the format `component: summary`, if possible.
* summary uses the imperative, present tense: "change", not "changed" or "changes"
  ([ref](http://git.kernel.org/cgit/git/git.git/tree/Documentation/SubmittingPatches?id=HEAD)).


## Bouncer configuration overview

A template for setting deployment options is provided by the file
`./tools/run-gunicorn-testconfig.sh`. Generally, the configuration is
comprised of two parts:

1. WSGI server configuration (see [gunicorn](http://gunicorn.org/)
2. Bouncer configuration

Bouncer is configured via the environment variable `BOUNCER_CONFIG_CLASS`
in combination with predefined configuration classes in `bouncer/config.py`.

If the environment variable `BOUNCER_CONFIG_FILE_PATH` is set, Bouncer reads
the file (expects flat JSON) and updates the configuration. That is, keys
specified in that JSON file take precedence over defaults defined in
`bouncer/config.py`.


## Debugging in production via SIGUSR2

Upon receiving a SIGUSR2 signal, a Bouncer worker process dumps a stack trace
for each thread (in the worker process) to stderr. The operation is intended to
not affect the health of the application. First, find out the process ID of a
worker process via e.g. `ps ax | grep 'gunicorn: worker'` and then send the
signal via e.g. `kill -SIGUSR2 27784`


## HTTP API specification

The file `docs/openapi-spec.yaml` specifies the behavior bouncer's HTTP API,
using [OpenAPI/Swagger 2.0 notation](https://github.com/swagger-api/swagger-spec).

For ease of viewing, the contents of `docs/openapi-spec.yaml` can be pasted
into the [Swagger editor](http://editor.swagger.io) — resulting in a useful
and beautiful HTML live-rendering of the API specification. Note that the
HTML output does not necessarily contain all detail specified in the YAML
file.

This spec also contains [JSON schema](http://json-schema.org/) definitions for
objects transferred in the body of requests/responses. For working with those,
it might be useful to work with `docs/openapi-spec.yaml`.
