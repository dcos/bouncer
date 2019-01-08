# Overview over make targets
#
# External interface:
#
# test: run complete test suite & validation logic (used in CI)
#
# clean: clean up after a previous run:
#
# 	- stop containers
#   - force-remove containers (their state, not the images), and volumes
#   - remove files from host filesystem
#
#
# run: run Bouncer in a container, expose HTTP API on host
#
#	- this uses tools/run-gunicorn-testconfig.sh
# 	- The database is SQLite in this case
#
#
# stop: stop Bouncer started via `make run`
#
#
# shell: call /bin/bash in the "devkit" container
#
#	- the devkit container contains all dependencies for running Bouncer
#	- the devkit container contains all dependencies for running the
#	  test runner
#	- this is convenient for custom invocation of the test runner
#	  (as opposed to the default behavior within `make test`
#
#
# rebuild-container-images: rebuild all relevant container images.
#
#	- this makes used of cached layers.
#	- for completely wiping previous container image state use docker
#	- commands manually (not supported by this Makefile)
#
#
# Internal:
#
# _remove-containers:
# 	- used within `clean`
# 	- used within `stop`
#
# _build-container-images-if-not-existing
# 	- used within almost all other targets.


.DEFAULT_GOAL := help
SHELL := /bin/bash

BOUNCER_LOCAL_PATH := $(CURDIR)
BOUNCER_CTR_MOUNT := /usr/local/src/bouncer

# Mount the host's /tmp directory into the test runner container so that
# temporary files created by the test runner can be mounted into containers
# started by the test runner (such containers are spawned on the host directly,
# and the host directory of a mount definition likewise must point to the real
# host's file system, and not to a directory only available in the test runner's
# container file system). Containers started by the test runner use the bridge
# network and port mappings. To make them accessible for the containerized test
# runner (the test runner can be launched in a container itself as it's done in
# the Jenkins CI via the very present Makefile) we used --net=host when invoking
# the test runner container. That is incompatible with Docker's user namespace
# support ("Cannot share the host's network namespace when user namespaces are
# enabled"). For that reason, start the test runner container in the default
# bridge networking mode and set up the custom DNS name
# `bouncer-test-hostmachine` (via the --add-host mechanism) which can be used
# for reaching the host machine.
DOCKER_NETWORK_HOST_IP=$(shell docker network inspect bridge -f "{{ with (index .IPAM.Config 0) }}{{ .Gateway }}{{ end }}")
DEVKIT_COMMON_DOCKER_OPTS := --name $(DEVKIT_CONTAINER_NAME) \
	-p 8101:8101 \
	--add-host="bouncer-test-hostmachine:${DOCKER_NETWORK_HOST_IP}" \
	--add-host="bouncer-test-hostmachine-alias:${DOCKER_NETWORK_HOST_IP}" \
	-e PYTHONDONTWRITEBYTECODE=true \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v $(BOUNCER_LOCAL_PATH):$(BOUNCER_CTR_MOUNT) \
	--tmpfs /gunicorn_tmp \
	-v /tmp:/tmp


.PHONY: help
help:
	@echo "Targets: test, run, stop, clean, shell, rebuild-container-images"


.PHONY: rebuild-container-images
rebuild-container-images:
	@echo "+ (Re)build devkit container image and periphery container images"
	docker build --rm --force-rm --tag $(DEVKIT_CONTAINER_IMAGE_TAG):latest $(BOUNCER_LOCAL_PATH)/
	# The following three are extension points for downstream, therefore optional.
	-docker build --rm --force-rm -t mesosphereci/bouncer-test-dex:latest $(BOUNCER_LOCAL_PATH)/tests/containers/dex/
	-docker build --rm --force-rm -t mesosphereci/bouncer-test-pysaml2-idp:latest $(BOUNCER_LOCAL_PATH)/tests/containers/pysaml2-idp/
	-docker build --rm --force-rm -t mesosphereci/bouncer-test-pyoidc-op2:latest $(BOUNCER_LOCAL_PATH)/tests/containers/pyoidc-op/


# Do not remove container images. Just clean up files in the current working
# directory that are a remainder of the last CI run. If you run this locally
# without Docker's user namespace support then these files are owned by root,
# and the cleanup will fail.
.PHONY: clean
clean: _remove-containers
	@echo "+ Remove files that a CI run might have left behind in the host filesystem"
	@find . -type f -name '*.pyc' -delete
	@find . -type f -name '.coverage.*' -delete
	@find . -type f -name '*.outerr' -delete
	@find . -name "__pycache__" -type d -prune -exec rm -r "{}" \;
	@rm -rf .cache
	@rm -rf coverage-report-html

.PHONY: shell
shell: _build-container-images-if-not-existing clean
	@echo "+ Run '/bin/bash' in devkit container"
	docker run --rm -it \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		$(DEVKIT_CONTAINER_IMAGE_TAG):latest /bin/bash

.PHONY: check-generated-files-up-to-date
check-generated-files-up-to-date: _build-container-images-if-not-existing clean
	@echo "+ Check if a database model migration is required (yes: bad)"
	docker run --rm \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		$(DEVKIT_CONTAINER_IMAGE_TAG):latest \
		python tools/generate_migration.py

.PHONY: test
test: _build-container-images-if-not-existing clean
	# --rm means: automatically remove the container when it exits
	@echo "+ Invoke flake8"
	docker run --rm \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		$(DEVKIT_CONTAINER_IMAGE_TAG):latest flake8 --verbose --exclude=alembic/versions
	@echo "+ Invoke pytest"
	docker run --rm \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		$(DEVKIT_CONTAINER_IMAGE_TAG):latest py.test --test-log-level=debug -vv -s

.PHONY: run
run: _build-container-images-if-not-existing clean
	@echo "+ Run 'run-gunicorn-testconfig.sh' in devkit container"
	docker run -d \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		$(DEVKIT_CONTAINER_IMAGE_TAG):latest tools/run-gunicorn-testconfig.sh
	@echo "Bouncer is running in the background, issue 'docker logs -f $(DEVKIT_CONTAINER_NAME)' for logs"

.PHONY: stop
stop: _remove-containers

# Make use of a technique top robustly invoke a different target in the same
# Makefile
.PHONY: _build-container-images-if-not-existing
_build-container-images-if-not-existing:
	@if $$(docker images | grep $(DEVKIT_CONTAINER_IMAGE_TAG) | grep -q latest); then \
		echo "+ Devkit & periphery containers seem to be already built. Do not rebuild."; \
	else \
		$(MAKE) -f $(THIS_FILE) rebuild-container-images; \
	fi

.PHONY: _remove-containers
_remove-containers:
	@echo "+ Force removal of devkit container and periphery containers, remove associated volumes"
	@-docker rm --force --volumes $(DEVKIT_CONTAINER_NAME) > /dev/null 2>&1
	@-docker rm --force --volumes bouncer-test-pyoidc-op2 > /dev/null 2>&1
	@-docker rm --force --volumes bouncer-test-pysaml2-idp > /dev/null 2>&1
	@-docker rm --force --volumes bouncer-test-dex > /dev/null 2>&1
