import pytest
import tests.containers


@pytest.fixture(scope='session')
def cockroach():
    cockroach = tests.containers.ContainerCockroach()
    try:
        cockroach.start_and_wait()
        yield cockroach
    finally:
        cockroach.close()


@pytest.fixture(scope='session')
def dex(tmpdir_factory):
    dex = tests.containers.ContainerDex(tmpdir_factory)
    try:
        dex.start_and_wait()
        yield dex
    finally:
        dex.close()


__all__ = ["cockroach", "dex"]
