"""
Utilities to create temporary files and directories.
"""

import tempfile


def new_tempdir():
    """Creates a new temporary directory."""
    return tempfile.mkdtemp(dir=".")


def new_named_tempfile(dir, mode="w", delete=True, suffix=""):
    """Creates a new temporary file."""
    return tempfile.NamedTemporaryFile(dir=dir, mode=mode, delete=delete, suffix=suffix)
