"""
Contains code for visualizing measurex's testcases using HTML.
"""

from __future__ import annotations
from typing import List, Optional, Iterator

import slugify
from yattag.simpledoc import SimpleDoc

from ..dataformat.testcase import EntryMeasurement, TestCase
from ..tabulatex import Tabular


def _test_case_filepath_slug(tc: TestCase):
    """Returns a slug for the filepath"""
    return slugify.slugify(tc.manifest().filepath)


def test_cases_overview(doc: SimpleDoc, tcs: List[TestCase]):
    """Generates a table with summary information on each test case."""
    columns: Optional[List[str]] = None
    with doc.tag("h1"):
        doc.text("Test cases")
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        with doc.tag("thead"):
            for tc in tcs:
                manifest = tc.manifest().as_tabular()
                columns = manifest.columns()
                with doc.tag("tr"):
                    for column in columns:
                        with doc.tag("th"):
                            doc.attr(title=f"click to sort by {column}")
                            doc.text(column)
                break
        with doc.tag("tbody"):
            for tc in tcs:
                manifest = tc.manifest().as_tabular()
                for row in manifest.rows():
                    with doc.tag("tr"):
                        slug = _test_case_filepath_slug(tc)
                        doc.attr(klass="starts-visible", id=f"summary-{slug}")
                        doc.attr(
                            onclick=f"makeVisible('measurements-{slug}'); return false;"
                        )
                        doc.attr(
                            title="click to show details (and escape to hide details)"
                        )
                        for entry in row:
                            with doc.tag("td"):
                                doc.text(entry)


def _test_case_tabular_info(doc: SimpleDoc, title: str, slug: str, tab: Tabular):
    """Generates information on all DNS measurements."""
    with doc.tag("h2"):
        doc.text(title)
    idx_index: Optional[int] = None
    with doc.tag("table"):
        doc.attr(klass="styled-table")
        with doc.tag("thead"):
            with doc.tag("tr"):
                for idx, column in enumerate(tab.columns()):
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
                            onclick=f"makeVisible('details-{slug}-{resultid}'); return false;"
                        )
                    for entry in row:
                        with doc.tag("td"):
                            doc.text(str(entry))


def _test_case_raw_info(doc: SimpleDoc, slug: str, entries: Iterator[EntryMeasurement]):
    for entry in entries:
        with doc.tag("pre"):
            doc.attr(style="display: none;")
            doc.attr(klass="starts-hidden details")
            doc.attr(id=f"details-{slug}-{entry.id()}")
            doc.text(entry.decode())


def test_case_info(doc: SimpleDoc, tc: TestCase):
    """Generates information on a single test case."""
    slug = _test_case_filepath_slug(tc)
    with doc.tag("div"):
        doc.attr(id=f"measurements-{slug}")
        doc.attr(klass="starts-hidden")
        with doc.tag("h1"):
            doc.text(tc.manifest().filepath)
        _test_case_tabular_info(
            doc, "DNS", slug, tc.cache().dns_measurements_as_tabular()
        )
        _test_case_raw_info(doc, slug, tc.cache().dns_measurements())
        _test_case_tabular_info(
            doc, "endpoint", slug, tc.cache().endpoint_measurements_as_tabular()
        )
        _test_case_raw_info(doc, slug, tc.cache().endpoint_measurements())
