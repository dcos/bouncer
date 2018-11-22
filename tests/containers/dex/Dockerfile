FROM golang:1.9-alpine

# Upgrade tar to get --strip-components support.
RUN set -ex \
    && apk add --update ca-certificates openssl wget make g++ tar bash

ENV GOPATH /gopath
ENV DEX_BUILD_DIR $GOPATH/src/github.com/coreos/dex

# Create build/source directory and /dex, the directory to store
# build artifacts to later on. CD to build dir.
RUN set -ex \
    && mkdir -p $DEX_BUILD_DIR \
    && mkdir /dex

WORKDIR $DEX_BUILD_DIR

# Download Dex tarball. Extract to current directory (build dir) and
# remove top-level directory upon extraction. Invoke build.
RUN set -ex \
    && wget -nv https://github.com/dexidp/dex/archive/v2.10.0.tar.gz \
    && tar xzf v2.10.0.tar.gz --strip-components 1 \
    && make

# Copy build artifacts to /dex.
RUN set -ex \
    && cp -a bin/dex /dex \
    && cp -a web /dex

WORKDIR /dex
COPY config.yaml config-for-bouncer-unit-tests.yaml

# These two files must be mounted into the container:
# /dexcerts/server.crt
# /dexcerts/server.key

ENV PATH /dex:$PATH
CMD ["dex", "serve", "config-for-bouncer-unit-tests.yaml"]
