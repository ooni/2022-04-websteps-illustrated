"""
This package contains extensions over the tabulate package.
"""

from __future__ import annotations

import tabulate

from typing import (
    Any,
    Callable,
    List,
    Optional,
    Tuple,
)


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

    def tabulatex(
        self, format: str = "grid", sortkey: Optional[Callable[[Any], Any]] = None
    ) -> str:
        """This function returns a representation of the values currently
        in the tables that is compatible with the given format.

        The supported formats are the same used by the tabulate library.

        The optional callable allows for specifying the sort key to be
        used before generating the textual representation.
        """
        rows = self._rows
        if sortkey is not None:
            rows = sorted(self._rows, key=sortkey)
        return tabulate.tabulate(rows, headers=self._columns, tablefmt=format)
