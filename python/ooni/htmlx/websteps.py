"""
Contains code to visualize websteps results using HTML.
"""

from __future__ import annotations

from ..dataformat.dblike import (
    DBLikeWebstepsTestKeys
)

from yattag.simpledoc import SimpleDoc

def websteps_measurement(doc: SimpleDoc, tks: DBLikeWebstepsTestKeys) -> str:
    """Transforms a websteps measurement into an HTML page."""
    return ""
