"""
Contains wrappers for probe-cli's internal/engine/experiment/websteps package.

See internal/engine/experiment/websteps/*.go
"""

from __future__ import annotations

from typing import (
    List,
    Optional,
    Tuple,
)

from .typecast import (
    DictWrapper,
    IntWrapper,
)

from .pkg_dnsping import (
    DNSPingArchivalResult,
)

from .pkg_measurex import (
    MeasurexArchivalDNSLookupMeasurement,
    MeasurexArchivalEndpointMeasurement,
    MeasurexArchivalURLMeasurement,
)


WEBSTEPS_FLAGS: List[Tuple[int, str]] = [
    (1 << 0, "#nxdomain"),
    (1 << 1, "#dnsTimeout"),
    (1 << 2, "#bogon"),
    (1 << 3, "#dnsNoAnswer"),
    (1 << 4, "#dnsRefused"),
    (1 << 5, "#dnsDiff"),
    (1 << 6, "#dnsServfail"),
    (1 << 7, "#tcpTimeout"),
    (1 << 8, "#tcpRefused"),
    (1 << 9, "#quicTimeout"),
    (1 << 10, "#tlsTimeout"),
    (1 << 11, "#tlsEOF"),
    (1 << 12, "#tlsReset"),
    (1 << 13, "#certificate"),
    (1 << 14, "#httpDiff"),
    (1 << 15, "#httpTimeout"),
    (1 << 16, "#httpReset"),
    (1 << 17, "#httpEOF"),
    (1 << 32, "#inconclusive"),
    (1 << 33, "#probeBug"),
    (1 << 34, "#httpDiffStatusCode"),
    (1 << 35, "#httpDiffTitle"),
    (1 << 36, "#httpDiffHeaders"),
    (1 << 37, "#httpDiffBodyLength"),
    (1 << 38, "#httpDiffLegitimateRedirect"),
    (1 << 39, "#httpDiffTransparentProxy"),
]


class WebstepsAnalysisFlagsWrapper:
    """Wraps websteps analysis flags."""

    def __init__(self, flags: int):
        self.flags = flags

    def tags(self) -> List[str]:
        """Converts flags to a list of tags."""
        out: List[str] = []
        for flag in WEBSTEPS_FLAGS:
            if (self.flags & flag[0]) != 0:
                out.append(flag[1])
        return out


class WebstepsAnalysisDNSOrEndpoint:
    """Corresponds to internal/engine/websteps.Analysis{DNS,Endpoint}."""

    def __init__(self, entry: DictWrapper):
        self.id = entry.getinteger("id")
        self.refs = [IntWrapper(x).unwrap() for x in entry.getlist("refs")]
        self.flags = WebstepsAnalysisFlagsWrapper(entry.getinteger("flags"))
        self.raw = entry.unwrap()


class WebstepsAnalysis:
    """Corresponds to internal/engine/websteps.Analysis."""

    def __init__(self, entry: DictWrapper):
        self.dns = [
            WebstepsAnalysisDNSOrEndpoint(DictWrapper(x)) for x in entry.getlist("dns")
        ]
        self.endpoint = [
            WebstepsAnalysisDNSOrEndpoint(DictWrapper(x))
            for x in entry.getlist("endpoint")
        ]
        self.th = [
            WebstepsAnalysisDNSOrEndpoint(DictWrapper(x)) for x in entry.getlist("th")
        ]
        self.raw = entry.unwrap()


class WebstepsArchivalTHResponse:
    """Corresponds to internal/engine/websteps.ArchivalTHResponse."""

    def __init__(self, entry: DictWrapper):
        self.dns = [
            MeasurexArchivalDNSLookupMeasurement(DictWrapper(x))
            for x in entry.getlist("dns")
        ]
        self.endpoint = [
            MeasurexArchivalEndpointMeasurement(DictWrapper(x))
            for x in entry.getlist("endpoint")
        ]
        self.raw = entry.unwrap()

    @staticmethod
    def optional(entry: DictWrapper) -> Optional[WebstepsArchivalTHResponse]:
        if not entry:
            return None
        return WebstepsArchivalTHResponse(entry)


class WebstepsArchivalSingleStepMeasurement:
    """Corresponds to internal/engine/websteps.ArchivalSingleStepMeasurement."""

    def __init__(self, entry: DictWrapper):
        # Since 2022-03-23, we're basically embedding an URLMeasurement
        # into the single step result in archival format to simplify
        # understanding and processing the measurement.
        malu = MeasurexArchivalURLMeasurement(entry)
        self.id = malu.id
        self.endpoint_ids = malu.endpoint_ids
        self.url = malu.url
        self.cookies = malu.cookies
        self.dns = malu.dns
        self.endpoint = malu.endpoint
        self.th = WebstepsArchivalTHResponse.optional(entry.getdictionary("th"))
        self.dnsping = DNSPingArchivalResult.optional(entry.getdictionary("dnsping"))
        self.probe_additional = [
            MeasurexArchivalEndpointMeasurement(DictWrapper(x))
            for x in entry.getlist("probe_additional")
        ]
        self.analysis = WebstepsAnalysis(entry.getdictionary("analysis"))
        self.flags = WebstepsAnalysisFlagsWrapper(entry.getinteger("flags"))
        self.raw = entry.unwrap()


class WebstepsArchivalTestKeys:
    """Corresponds to internal/engine/websteps.ArchivalTestKeys."""

    def __init__(self, tks: DictWrapper):
        self.url = tks.getstring("url")
        self.steps = [
            WebstepsArchivalSingleStepMeasurement(DictWrapper(x))
            for x in tks.getlist("steps")
        ]
        self.flags = WebstepsAnalysisFlagsWrapper(tks.getinteger("flags"))
        self.raw = tks.unwrap()