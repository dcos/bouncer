import atexit
import logging
import os
import shutil
import tempfile


log = logging.getLogger(__name__)


def set_up_app_tempdir(name, cleanup_dir=True):
    """Securely set up a temporary directory for the application to use. Perform
    a best-effort cleanup during startup and shutdown.

    Use `tempfile.gettempdir()` to obtain a suitable directory that can be used
    for storing temporary files (usually `/tmp`). Create a directory named
    `{name}` in there, using `os.makedirs()`. Subsequently, place a secure
    temporary directory in there via `tempfile.mkdtemp()`. The latter is the
    temporary directory exposed to the application.

    If `/tmp/{name}` exists upon startup, attempt to remove it recursively. Do
    the same upon clean interpreter exit.

    Args:
        name: Name of temporary directory
        cleanup_dir: Whether we should attempt to clean up directory on app
            exit.
    """
    tmpdir = tempfile.gettempdir()
    app_tempdir_parent = os.path.join(tmpdir, name)

    def _remove_app_tempdir_parent():
        # Use a best-effort approach to remove remainders from previous runs,
        # via recursive removal of the parent directory containing the actual
        # payload. Disable this cleanup in TESTING mode as there may be multiple
        # Bouncer instances running simultaneously.
        if cleanup_dir:
            if os.path.isdir(app_tempdir_parent):
                log.info('Attempt to remove directory: %s', app_tempdir_parent)
                shutil.rmtree(app_tempdir_parent, ignore_errors=True)

    _remove_app_tempdir_parent()
    log.info('Attempt to create directory: %s', app_tempdir_parent)
    try:
        os.makedirs(app_tempdir_parent)
    except OSError as e:
        # Let this error not be fatal, because `mkdtemp(dir=app_tempdir_parent)`
        # below might still succeed.
        log.warning('Could not os.makedirs(%s): %s', app_tempdir_parent, e)

    # Best-effort cleanup upon exit (only triggered upon sane interpreter exit).
    atexit.register(_remove_app_tempdir_parent)

    # Create secure temporary directory.
    app_tempdir_abspath = tempfile.mkdtemp(dir=app_tempdir_parent)
    log.info('Created temporary directory: %s', app_tempdir_abspath)
    return app_tempdir_abspath
