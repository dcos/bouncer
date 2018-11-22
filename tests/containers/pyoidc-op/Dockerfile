FROM python:3.6.6

# Requirements for running pyoidc's OP2 demo:
# * pip install https://pypi.python.org/pypi/oic
# * pip install https://pypi.python.org/pypi/pysaml2
# * pip install https://pypi.python.org/pypi/CherryPy
# * Repo checkout, config file copying & editing

WORKDIR /

# Install dependencies.
# Note(JP, 2018): I have tried to bump this to oic 0.14.0 and more recent
# versions of cherrypy, and also to a more recent version of the "OP2" demo.
# My conclusion is that the demo has been developed against oic==0.9.1.0 and
# cherrypy 8.x.x and that bumping any of the named modules results in
# code breakages.
RUN set -ex \
    && pip install 'oic==0.9.1.0' 'pysaml2==4.3.0' 'cherrypy==8.9.1' six

# Quick & dirty way for running the OP2 example.
RUN set -ex \
    && git clone https://github.com/OpenIDC/pyoidc pyoidc \
    && cd pyoidc \
    && git reset --hard d3ea1d15814f9268e3588b49c133b53450fb89df \
    && cd oidc_example/op2 \
    && cp config.py.simple config.py

# By default, the OP reads the certificate (and key) file from
# /pyoidc/oidc_example/op2/certs/server.crt(.key)
# These are dynamically injected by the test runner infrastructure via mounting
# in a certs directory to `/pyoidc/oidc_example/op2/certs` (in the container fs,
# overlaying the default).

WORKDIR /pyoidc/oidc_example/op2
EXPOSE 8092

# The run command is defined in bouncer/tests/containers/oidc.py
