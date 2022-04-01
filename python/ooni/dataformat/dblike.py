"""
Database-like abstraction over websteps measurements.

It may be useful to construct analysis tools. So, it's a separate layer
that you can overlay on top of the archival module.
"""

from __future__ import annotations

from enum import Enum
import traceback

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Protocol,
)

from .archival import (
    WebstepsAnalysis,
    WebstepsAnalysisDNSOrEndpoint,
    MeasurexDNSLookupMeasurement,
    DNSPingResult,
    DNSPingSinglePingResult,
    DNSPingSinglePingReply,
    MeasurexEndpointMeasurement,
    WebstepsSingleStepMeasurement,
    WebstepsTHResponse,
    WebstepsTestKeys,
)

from ..tabulatex import (
    Tabular,
)

from . import jsonl


class DBLikeKind(Enum):
    """The kind of an entry."""

    ANALYSIS = "analysis"
    DNS = "dns"
    DNS_SINGLE_PING_RESULT = "dns_single_ping_result"
    DNS_SINGLE_PING_REPLY = "dns_single_ping_reply"
    ENDPOINT = "endpoint"
    NONE = ""
    URL = "url"


class DBLikeOrigin(Enum):
    """The origin of an entry."""

    NONE = ""
    PROBE = "probe"
    TH = "th"

    def __str__(self):
        return self.value


class DBLikeEntry(Protocol):
    """An entry into the MeasurementDB structure."""

    def tabular(self) -> Tabular:
        """Converts this entry to a tabular."""
        return Tabular()

    def step_id(self) -> int:
        """Returns the ID of the step owning this measurement."""
        return 0

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return 0

    def kind(self) -> DBLikeKind:
        """Returns the kind of this entry."""
        return DBLikeKind.NONE

    def origin(self) -> DBLikeOrigin:
        """Returns the origin of this entry."""
        return DBLikeOrigin.NONE

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return {}

    def unwrap(self) -> Any:
        """Returns the underlying object"""
        return None


def entries_to_tabular(entries: List[DBLikeEntry]) -> Tabular:
    """Converts a list of entries to the tabular format."""
    tab = Tabular()
    for entry in entries:
        tab.append(entry.tabular())
    return tab


class DBLikeURLMeasurement:
    """Wrapper for MeasurexURLMeasurement."""

    def __init__(self, ssm: WebstepsSingleStepMeasurement):
        self._ssm = ssm

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("id", self._ssm.id),
                ("endpoint_ids", self._ssm.endpoint_ids),
                ("url", self._ssm.url),
                ("cookies", self._ssm.cookies),
                ("dns", [x.id for x in self._ssm.dns]),
                ("endpoint", [x.id for x in self._ssm.endpoint]),
            ]
        )

    def step_id(self) -> int:
        return self._ssm.id

    def id(self) -> int:
        return self._ssm.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.URL

    def origin(self) -> DBLikeOrigin:
        return DBLikeOrigin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._ssm.raw

    def unwrap(self) -> Any:
        return self._ssm


class DBLikeDNSLookupMeasurement:
    """Wrapper for a MeasurexDNSLookupMeasurement."""

    def __init__(
        self, step_id: int, origin: DBLikeOrigin, dns: MeasurexDNSLookupMeasurement
    ):
        self._step_id = step_id
        self._dns = dns
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("step_id", self._step_id),
                ("id", self._dns.id),
                ("origin", self._origin),
                ("resolver", self._dns.resolver_url()),
                ("lookup_types", self._dns.lookup_types()),
                ("domain", self._dns.domain),
                ("failure", self._dns.failure),
                ("addresses", self._dns.addresses),
                ("ptrs", self._dns.ptrs()),
            ]
        )

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._dns.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.DNS

    def origin(self) -> DBLikeOrigin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._dns.raw

    def unwrap(self) -> Any:
        return self._dns


class DBLikeEndpointMeasurement:
    """Wrapper for and MeasurexEndpointMeasurement."""

    def __init__(
        self, step_id: int, origin: DBLikeOrigin, epnt: MeasurexEndpointMeasurement
    ):
        self._step_id = step_id
        self._epnt = epnt
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("step_id", self._step_id),
                ("id", self._epnt.id),
                ("origin", self._origin),
                ("url", self._epnt.url),
                ("network", self._epnt.network),
                ("address", self._epnt.address),
                ("cookies_names", self._epnt.cookies_names),
                ("failed_operation", self._epnt.failed_operation),
                ("failure", self._epnt.failure),
                ("location", self._epnt.location),
                ("title", self._epnt.title),
                ("status", self._epnt.status_code),
                ("body_len", self._epnt.body_length),
            ]
        )

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._epnt.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.ENDPOINT

    def origin(self) -> DBLikeOrigin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._epnt.raw

    def unwrap(self) -> Any:
        return self._epnt


class DBLikeAnalysis:
    """Wrapper for WebstepsAnalysisDNSOrEndpoint."""

    def __init__(
        self,
        step_id: int,
        origin: DBLikeOrigin,
        analysis: WebstepsAnalysisDNSOrEndpoint,
    ):
        self._step_id = step_id
        self._analysis = analysis
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("step_id", self._step_id),
                ("id", self._analysis.id),
                ("refs", self._analysis.refs),
                ("flags", self._analysis.flags.tags()),
            ]
        )

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._analysis.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.ANALYSIS

    def origin(self) -> DBLikeOrigin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._analysis.raw

    def unwrap(self) -> Any:
        return self._analysis


class DBLikeDNSPingSinglePingReply:
    """Wrapper for DNSPingSinglePingResult."""

    def __init__(self, step_id: int, reply: DNSPingSinglePingReply):
        self._step_id = step_id
        self._reply = reply

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("step_id", self._step_id),
                ("id", self._reply.id),
                ("source_address", self._reply.source_address),
                ("failure", self._reply.failure),
                ("t", self._reply.t),
                ("reply", self._reply.reply),
                ("addresses", self._reply.addresses),
                ("alpns", self._reply.alpns),
            ]
        )

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._reply.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.DNS_SINGLE_PING_REPLY

    def origin(self) -> DBLikeOrigin:
        return DBLikeOrigin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._reply.raw

    def unwrap(self) -> Any:
        return self._reply


class DBLikeDNSPingSinglePingResult:
    """Wrapper for DNSPingSinglePingResult."""

    def __init__(self, step_id: int, ping: DNSPingSinglePingResult):
        self._step_id = step_id
        self._ping = ping

    def tabular(self) -> Tabular:
        return Tabular.create(
            [
                ("step_id", self._step_id),
                ("id", self._ping.id),
                ("hostname", self._ping.hostname),
                ("query", self._ping.query),
                ("replies", [x.id for x in self._ping.replies]),
                ("resolver_address", self._ping.resolver_address),
                ("t", self._ping.t),
            ]
        )

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._ping.id

    def kind(self) -> DBLikeKind:
        return DBLikeKind.DNS_SINGLE_PING_RESULT

    def origin(self) -> DBLikeOrigin:
        return DBLikeOrigin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._ping.raw

    def unwrap(self) -> Any:
        return self._ping


class DBLikeWebstepsTestKeys:
    """Database-like access to websteps measurements."""

    def __init__(self, meas: WebstepsTestKeys):
        self._meas = meas
        self._table: Dict[int, DBLikeEntry] = {}
        self._load(meas)

    def tabular(self) -> Tabular:
        """Converts to tabular format."""
        return Tabular.create(
            [
                ("url", self.url()),
                ("tags", self.tags()),
            ]
        )

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this database."""
        return self._meas.raw

    def tags(self) -> List[str]:
        """Returns the measurement tags."""
        return self._meas.flags.tags()

    def url(self) -> str:
        """Returns the measurement URL."""
        return self._meas.url

    def list_analysis(self, url_idx: Optional[int] = None) -> List[DBLikeEntry]:
        """Returns all the analysis entries."""
        out: List[DBLikeEntry] = []
        for entry in self._table.values():
            if entry.kind() != DBLikeKind.ANALYSIS:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_dns(self, url_idx: Optional[int]) -> List[DBLikeEntry]:
        """Returns all the dns entries."""
        out: List[DBLikeEntry] = []
        for entry in self._table.values():
            if entry.kind() != DBLikeKind.DNS:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_endpoint(self, url_idx: Optional[int]) -> List[DBLikeEntry]:
        """Returns all the endpoint entries."""
        out: List[DBLikeEntry] = []
        for entry in self._table.values():
            if entry.kind() != DBLikeKind.ENDPOINT:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_urls(self) -> List[DBLikeEntry]:
        """Returns the list of URLs measured in this measurement."""
        out: List[DBLikeEntry] = []
        for entry in self._table.values():
            if entry.kind() == DBLikeKind.URL:
                out.append(entry)
        return out

    def find_entry(self, id: int) -> DBLikeEntry:
        """Returns the entry with the given ID or throws KeyError."""
        return self._table[id]

    def _load(self, meas: WebstepsTestKeys):
        for step in meas.steps:
            self._load_probe_initial(step)
            self._load_th(step.id, step.th)
            self._load_dnsping(step.id, step.dnsping)
            self._load_probe_additional(step.id, step.probe_additional)
            self._load_analysis(step.id, step.analysis)

    def _load_probe_initial(self, ssm: WebstepsSingleStepMeasurement):
        self._table[ssm.id] = DBLikeURLMeasurement(ssm)
        for d in ssm.dns:
            self._load_dns(ssm.id, DBLikeOrigin.PROBE, d)
        for e in ssm.endpoint:
            self._load_endpoint(ssm.id, DBLikeOrigin.PROBE, e)

    def _load_th(self, step_id: int, th: Optional[WebstepsTHResponse]):
        if th is not None:
            for dns in th.dns:
                self._load_dns(step_id, DBLikeOrigin.TH, dns)
            for epnt in th.endpoint:
                self._load_endpoint(step_id, DBLikeOrigin.TH, epnt)

    def _load_dnsping(self, step_id: int, dnsping: Optional[DNSPingResult]):
        if dnsping is not None:
            for ping in dnsping.pings:
                self._table[ping.id] = DBLikeDNSPingSinglePingResult(step_id, ping)
                for reply in ping.replies:
                    self._table[reply.id] = DBLikeDNSPingSinglePingReply(step_id, reply)

    def _load_probe_additional(
        self, step_id: int, epnts: List[MeasurexEndpointMeasurement]
    ):
        for epnt in epnts:
            self._load_endpoint(step_id, DBLikeOrigin.PROBE, epnt)

    def _load_analysis(self, step_id: int, analysis: Optional[WebstepsAnalysis]):
        if analysis is not None:
            for dns in analysis.dns:
                self._table[dns.id] = DBLikeAnalysis(step_id, DBLikeOrigin.PROBE, dns)
            for epnt in analysis.endpoint:
                self._table[epnt.id] = DBLikeAnalysis(step_id, DBLikeOrigin.PROBE, epnt)
            for th in analysis.th:
                self._table[th.id] = DBLikeAnalysis(step_id, DBLikeOrigin.PROBE, th)

    def _load_dns(
        self, step_id: int, origin: DBLikeOrigin, dns: MeasurexDNSLookupMeasurement
    ):
        self._table[dns.id] = DBLikeDNSLookupMeasurement(step_id, origin, dns)

    def _load_endpoint(
        self, step_id: int, origin: DBLikeOrigin, epnt: MeasurexEndpointMeasurement
    ):
        self._table[epnt.id] = DBLikeEndpointMeasurement(step_id, origin, epnt)


def load(filepath: str) -> List[DBLikeWebstepsTestKeys]:
    """Loads measurements from a JSONL file and returns them
    as a list of DBLike Websteps Test Keys."""
    out: List[DBLikeWebstepsTestKeys] = []
    for measurement in jsonl.reader(filepath):
        try:
            meas = WebstepsTestKeys(measurement.getdictionary("test_keys"))
        except ValueError:
            traceback.print_exc()
            raise
        mdb = DBLikeWebstepsTestKeys(meas)
        out.append(mdb)
    return out
