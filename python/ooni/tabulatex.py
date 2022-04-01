"""
This package contains extensions over the tabulate package.
"""

from __future__ import annotations
import json
import random

import tabulate

from typing import (
    Any,
    Callable,
    List,
    Optional,
    OrderedDict,
    Protocol,
    Tuple,
)


class Tabulable(Protocol):
    """Anything that can be tabulated."""

    def tabular(self) -> Tabular:
        """Converts this thing into a tabular."""
        return Tabular()


class Tabular:
    """Tabular contains tabular data that you can format using the tabulatex method."""

    def __init__(self):
        self._columns: List[str] = []
        self._rows: List[List[Any]] = []

    def columns(self) -> List[str]:
        """Returns the table columns"""
        return self._columns

    def rows(self) -> List[Any]:
        """Returns the table rows"""
        return self._rows

    @staticmethod
    def create(pairs: List[Tuple[str, Any]]) -> Tabular:
        tab = Tabular()
        row: List[Any] = []
        for key, val in pairs:
            tab._columns.append(key)
            row.append(val)
        tab._rows.append(row)
        return tab

    def append(self, tab: Tabular):
        """Appends the given tabular to the current tabular, if the
        columns are compatible, otherwise raise TypeError."""
        if not tab.columns:
            return
        if not self._columns:
            self._columns = tab._columns
            self._rows = tab._rows
            return
        if self._columns != tab._columns:
            raise TypeError("incompatible columns")
        self._rows.extend(tab._rows)

    def appendrow(self, pairs: List[Tuple[str, Any]]):
        """Appends a single row generated on the fly from the given pairs"""
        self.append(self.create(pairs))

    def shuffle(self):
        """Shuffles the rows"""
        random.shuffle(self._rows)

    def shrink(self, n: int):
        """Resize the tabular to only contain N rows."""
        if n < len(self._rows):
            self._rows = self._rows[:n]

    def __len__(self) -> int:
        return len(self._rows)

    def tabulatex(
        self, format: str = "grid", sortkey: Optional[Callable[[Any], Any]] = None
    ) -> str:
        """This function returns a representation of the values currently
        in the tables that is compatible with the given format.

        If the format argument is JSON we'll construct an ordered dict out of
        each row and the column names and we'll emit that. Otherwise, we'll just
        pass the format argument through to tabulate.

        The optional callable allows for specifying the sort key to be
        used before generating the textual representation.
        """
        rows = self._rows
        if sortkey is not None:
            rows = sorted(self._rows, key=sortkey)
        if format == "json":
            out = []
            for row in rows:
                out.append(OrderedDict(zip(self._columns, row)))
            # See https://stackoverflow.com/a/64469761
            return json.dumps(out, default=vars)
        return tabulate.tabulate(rows, headers=self._columns, tablefmt=format)
