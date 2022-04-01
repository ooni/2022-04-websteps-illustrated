"""
Contains code to visualize websteps results using HTML.
"""

from __future__ import annotations
from typing import List, Optional

from ..dataformat import dblikedecode
from ..dataformat import dblike

from ..dataformat.dblike import (
    DBLikeEntry,
    DBLikeWebstepsTestKeys,
)

from ..tabulatex import Tabular

from yattag.simpledoc import SimpleDoc


def _websteps_steps(doc: SimpleDoc, tks: DBLikeWebstepsTestKeys):
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        tab = dblike.entries_to_tabular(tks.list_urls())
        with doc.tag("thead"):
            with doc.tag("tr"):
                for column in tab.columns():
                    with doc.tag("th"):
                        doc.attr(title=f"click to sort by {column}")
                        doc.text(column)
        with doc.tag("tbody"):
            for row in tab.rows():
                with doc.tag("tr"):
                    for r in row:
                        with doc.tag("td"):
                            doc.text(str(r))


def _websteps_dns(doc: SimpleDoc, dns: List[DBLikeEntry]):
    # Implementation note: sharing the implemntation with the endpoint
    # function because both have exactly the same needs
    _websteps_endpoint(doc, dns)


def _websteps_endpoint(doc: SimpleDoc, epnt: List[DBLikeEntry]):
    tab = dblike.entries_to_tabular(epnt)
    idx_index: Optional[int] = None
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        with doc.tag("thead"):
            with doc.tag("tr"):
                for idx, column in enumerate(tab.columns()):
                    # TODO(bassosimone): teach a tabular to tell me exactly
                    # which is the index of the id column
                    if column == "id":
                        idx_index = idx
                    with doc.tag("th"):
                        doc.attr(title=f"click to sort by {column}")
                        doc.text(column)
        with doc.tag("tbody"):
            for row in tab.rows():
                resultid: Optional[int] = None
                if idx_index is not None:
                    resultid = int(row[idx_index])
                with doc.tag("tr"):
                    doc.attr(title="click to show details (and escape to hide details)")
                    if resultid is not None:
                        doc.attr(
                            onclick=f"makeVisible('details-{resultid}'); return false;"
                        )
                    for r in row:
                        with doc.tag("td"):
                            doc.text(str(r))
    for e in epnt:
        with doc.tag("pre"):
            doc.attr(style="display: none;")
            doc.attr(klass="starts-hidden details")
            doc.attr(id=f"details-{e.id()}")
            doc.text(dblikedecode.entry(e))


def _websteps_analysis(doc: SimpleDoc, analysis: List[DBLikeEntry]):
    tab = dblike.entries_to_tabular(analysis)
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        with doc.tag("thead"):
            with doc.tag("tr"):
                for column in tab.columns():
                    with doc.tag("th"):
                        doc.attr(title=f"click to sort by {column}")
                        doc.text(column)
        with doc.tag("tbody"):
            for row in tab.rows():
                with doc.tag("tr"):
                    for r in row:
                        with doc.tag("td"):
                            doc.text(str(r))


def websteps_measurement(doc: SimpleDoc, tks: DBLikeWebstepsTestKeys):
    """Transforms a websteps measurement into an HTML page."""
    with doc.tag("h1"):
        doc.text("Steps")
    _websteps_steps(doc, tks)
    with doc.tag("h1"):
        doc.text("Analysis")
    _websteps_analysis(doc, tks.list_analysis(None))
    with doc.tag("h1"):
        doc.text("DNS")
    _websteps_dns(doc, tks.list_dns(None))
    with doc.tag("h1"):
        doc.text("Endpoint")
    _websteps_endpoint(doc, tks.list_endpoint(None))
