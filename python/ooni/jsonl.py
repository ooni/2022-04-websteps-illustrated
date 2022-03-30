"""
Contains code for reading JSONL files.
"""

from __future__ import annotations
import json
import gzip

from typing import (
    Iterator,
)

from .dataformat.typecast import (
    DictWrapper,
)


def reader(filepath: str) -> Iterator[DictWrapper]:
    """Reads a JSONL file yielding each measurement already
    casted as a DictWrapper type. To continue reading you
    will need to extract the test keys."""
    openerFactory = {
        True: gzip.open,
        False: open,
    }
    opener = openerFactory[filepath.endswith(".gz")]
    with opener(filepath, "rb") as filep:
        for line in filep:
            yield DictWrapper(json.loads(line))
