"""
Contains code to visualize websteps results using HTML.
"""

from __future__ import annotations
from typing import List

from ..dataformat.dblike import (
    DBLikeEntry,
    DBLikeWebstepsTestKeys,
)

from ..tabulatex import Tabular

from yattag.simpledoc import SimpleDoc


def _websteps_steps(doc: SimpleDoc, tks: DBLikeWebstepsTestKeys):
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        tab = Tabular.mapcreate(tks.list_urls())
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
    tab = Tabular.mapcreate(dns)
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


def _websteps_endpoint(doc: SimpleDoc, epnt: List[DBLikeEntry]):
    tab = Tabular.mapcreate(epnt)
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


def _websteps_analysis(doc: SimpleDoc, analysis: List[DBLikeEntry]):
    tab = Tabular.mapcreate(analysis)
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
