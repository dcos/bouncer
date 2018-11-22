# Set variables which can be overwritten downstream (using a different
# `Makefile`, and the same `common.mk`).
DEVKIT_CONTAINER_IMAGE_TAG = mesosphereci/bouncer-devkit
DEVKIT_CONTAINER_NAME = bouncer-devkit

# Used in common.mk for reliably calling a Makefile target within a recipe.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

include common.mk
