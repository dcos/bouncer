FROM python:3.6.13

# `apt-get update` and `apt-get install` are unreliable and http-redir service
# seems to be unmaintained. Because of that there is some basic retrying logic
# and apt is reconfigured to use deb.debian.org for mirrors. Please check
# https://lists.debian.org/debian-project/2016/04/msg00018.html
# http://deb.debian.org/
# https://github.com/tianon/docker-brew-debian/issues/37#issuecomment-254251021
# Also, attempt to fix
#    Could not open lock file /var/cache/apt/archives/lock - open (2: No such file or directory)
# via /var/cache/apt file hierarchy recreation.
RUN set -ex \
    && mkdir -p /var/cache/apt/archives/partial && touch /var/cache/apt/archives/lock && chmod 640 /var/cache/apt/archives/lock \
    && apt-get clean \
    && sed -i -e 's/httpredir.debian.org/deb.debian.org/g' /etc/apt/sources.list \
    && bash -x -c 'for i in {1..5}; do apt-get update && break || sleep 2; done' \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        curl \
        dnsutils net-tools \
        gcc \
        gnupg-agent \
        less \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        nano \
        ncat \
        python3-dev \
        software-properties-common

# The unit test suite requires running the docker client binary. As the binary
# from the host is usually linked against system libraries (which are usually
# not available within the container), a simple mount is not sufficient.
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add - \
    && add-apt-repository \
"deb [arch=amd64] https://download.docker.com/linux/debian \
$(lsb_release -cs) \
stable" \
    && apt-get update \
    && apt-get install -y docker-ce-cli

# Upgrading pip/setuptools and making the upgrade actually apply in the
# following filesystem layers works more reliable when using a virtualenv for
# creating the Python environment, especially on overlayfs.
# Refs:
#   https://github.com/docker/docker/issues/12327#issuecomment-188921470
#   https://github.com/docker/docker/issues/12327#issuecomment-187158265
# Not yet compatible with virtualenv 20+
RUN python -m pip install --upgrade 'virtualenv<20'

# Ensure that no previous PYTHONPATH pollution affects the creation of this
# virtualenv. Ref: http://stackoverflow.com/a/15887589/145400
RUN unset PYTHONPATH

RUN virtualenv --no-site-packages /venv \
    && /venv/bin/pip install --upgrade setuptools 'pip<20.3'

# Copy Bouncer's requirements files into the image (if they change,
# the image needs to be rebuilt).
COPY ./requirements*.txt ./

# Activate virtualenv. Start with installing Cython, so that it is
# available during subsequent package installs.
RUN /bin/bash -x -c " \
    source /venv/bin/activate && \
    export PYTHONIOENCODING=utf-8 && \
    pip install "$(cat requirements.txt | grep Cython)" && \
    pip install -r requirements.txt && \
    pip install -r requirements-tests.txt"

# Optionally install more Python packages.
RUN /bin/bash -x -c " \
    source /venv/bin/activate && \
    export PYTHONIOENCODING=utf-8 && \
    pip install -r requirements-extension.txt; exit 0"

# Ensure that the venv's bin directory is first in PATH
ENV PATH /venv/bin:$PATH

# Switch to Bouncer's directory.
WORKDIR /usr/local/src/bouncer

EXPOSE 8101

CMD ["/bin/bash"]
