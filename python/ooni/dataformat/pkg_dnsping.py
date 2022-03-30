"""
Contains wrappers for probe-cli's internal/dnsping package.

See internal/dnsping/*.go
"""

from __future__ import annotations
from typing import (
    Optional,
)

from .pkg_archival import (
    ArchivalBinaryData,
)

from .typecast import (
    DictWrapper,
    StrWrapper,
)


class DNSPingArchivalSinglePingReply:
    """Corresponds to internal/dnsping.ArchivalSinglePingReply."""

    def __init__(self, entry: DictWrapper):
        self.addresses = [StrWrapper(x).unwrap() for x in entry.getlist("addresses")]
        self.alpns = [StrWrapper(x).unwrap() for x in entry.getlist("alpns")]
        self.failure = entry.getfailure("failure")
        self.id = entry.getinteger("id")
        self.rcode = entry.getstring("rcode")
        self.reply = ArchivalBinaryData.optional(entry.getdictionary("reply"))
        self.source_address = entry.getstring("source_address")
        self.t = entry.getfloat("t")
        self.raw = entry.unwrap()


class DNSPingArchivalSinglePingResult:
    """Corresponds to internal/dnsping.ArchivalSinglePingResult."""

    def __init__(self, entry: DictWrapper):
        self.hostname = entry.getstring("hostname")
        self.id = entry.getinteger("id")
        self.query = ArchivalBinaryData.optional(entry.getdictionary("query"))
        self.query_id = entry.getinteger("query_id")
        self.query_type = entry.getstring("query_type")
        self.resolver_address = entry.getstring("resolver_address")
        self.t = entry.getfloat("t")
        self.replies = [
            DNSPingArchivalSinglePingReply(DictWrapper(x))
            for x in entry.getlist("replies")
        ]
        self.raw = entry.unwrap()


class DNSPingArchivalResult:
    """Corresponds to internal/dnsping.ArchivalResult."""

    def __init__(self, entry: DictWrapper):
        self.pings = [
            DNSPingArchivalSinglePingResult(DictWrapper(x))
            for x in entry.getlist("pings")
        ]
        self.raw = entry.unwrap()

    @staticmethod
    def optional(entry: DictWrapper) -> Optional[DNSPingArchivalResult]:
        if not entry:
            return None
        return DNSPingArchivalResult(entry)
