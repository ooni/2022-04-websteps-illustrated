"""Database-like abstraction over websteps measurements."""

from __future__ import annotations

from enum import Enum

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Protocol,
)
from urllib.parse import urlunparse

from ooni.dataformat.archival import (
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

from ooni.tabulatex import (
    Tabular,
)


class Kind(Enum):
    """The kind of an entry."""

    ANALYSIS = "analysis"
    DNS = "dns"
    DNS_SINGLE_PING_RESULT = "dns_single_ping_result"
    DNS_SINGLE_PING_REPLY = "dns_single_ping_reply"
    ENDPOINT = "endpoint"
    NONE = ""
    URL = "url"


class Origin(Enum):
    """The origin of an entry."""

    NONE = ""
    PROBE = "probe"
    TH = "th"


class Entry(Protocol):
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

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.NONE

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return Origin.NONE

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return {}

    def unwrap(self) -> Any:
        """Returns the underlying object"""
        return None


class URLMeasurementWrapper:
    """Wrapper for MeasurexURLMeasurement."""

    def __init__(self, ssm: WebstepsSingleStepMeasurement):
        self._ssm = ssm

    def tabular(self) -> Tabular:
        return Tabular.create([
            ("id", self._ssm.id),
            ("endpoint_ids", self._ssm.endpoint_ids),
            ("url", self._ssm.url),
            ("cookies", self._ssm.cookies),
            ("dns", [x.id for x in self._ssm.dns]),
            ("endpoint", [x.id for x in self._ssm.endpoint]),
        ])

    def step_id(self) -> int:
        return self._ssm.id

    def id(self) -> int:
        return self._ssm.id

    def kind(self) -> Kind:
        return Kind.URL

    def origin(self) -> Origin:
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._ssm.raw

    def unwrap(self) -> Any:
        return self._ssm


class DNSLookupMeasurementWrapper:
    """Wrapper for a MeasurexDNSLookupMeasurement."""

    def __init__(self, step_id: int, origin: Origin, dns: MeasurexDNSLookupMeasurement):
        self._step_id = step_id
        self._dns = dns
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create([
            ("step_id", self._step_id),
            ("id", self._dns.id),
            ("origin", self._origin),
            ("resolver", self._dns.resolver_url()),
            ("lookup_types", self._dns.lookup_types()),
            ("domain", self._dns.domain),
            ("failure", self._dns.failure),
            ("addresses", self._dns.addresses),
            ("ptrs", self._dns.ptrs())
        ])

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._dns.id

    def kind(self) -> Kind:
        return Kind.DNS

    def origin(self) -> Origin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._dns.raw

    def unwrap(self) -> Any:
        return self._dns


class EndpointMeasurementWrapper:
    """Wrapper for and MeasurexEndpointMeasurement."""

    def __init__(self, step_id: int, origin: Origin, epnt: MeasurexEndpointMeasurement):
        self._step_id = step_id
        self._epnt = epnt
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create([
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
        ])

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._epnt.id

    def kind(self) -> Kind:
        return Kind.ENDPOINT

    def origin(self) -> Origin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._epnt.raw

    def unwrap(self) -> Any:
        return self._epnt


class AnalysisDNSOrEndpointWrapper:
    """Wrapper for WebstepsAnalysisDNSOrEndpoint."""

    def __init__(self, step_id: int, origin: Origin, analysis: WebstepsAnalysisDNSOrEndpoint):
        self._step_id = step_id
        self._analysis = analysis
        self._origin = origin

    def tabular(self) -> Tabular:
        return Tabular.create([
            ("step_id", self._step_id),
            ("id", self._analysis.id),
            ("refs", self._analysis.refs),
            ("flags", self._analysis.flags.tags()),
        ])

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._analysis.id

    def kind(self) -> Kind:
        return Kind.ANALYSIS

    def origin(self) -> Origin:
        return self._origin

    def raw(self) -> Dict[str, Any]:
        return self._analysis.raw

    def unwrap(self) -> Any:
        return self._analysis


class DNSSinglePingReplyWrapper:
    """Wrapper for DNSPingSinglePingResult."""

    def __init__(self, step_id: int, reply: DNSPingSinglePingReply):
        self._step_id = step_id
        self._reply = reply

    def tabular(self) -> Tabular:
        return Tabular.create([
            ("step_id", self._step_id),
            ("id", self._reply.id),
            ("source_address", self._reply.source_address),
            ("failure", self._reply.failure),
            ("t", self._reply.t),
            ("reply", self._reply.reply),
            ("addresses", self._reply.addresses),
            ("alpns", self._reply.alpns),
        ])

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._reply.id

    def kind(self) -> Kind:
        return Kind.DNS_SINGLE_PING_REPLY

    def origin(self) -> Origin:
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._reply.raw

    def unwrap(self) -> Any:
        return self._reply


class DNSSinglePingResultWrapper:
    """Wrapper for DNSPingSinglePingResult."""

    def __init__(self, step_id: int, ping: DNSPingSinglePingResult):
        self._step_id = step_id
        self._ping = ping

    def tabular(self) -> Tabular:
        return Tabular.create([
            ("step_id", self._step_id),
            ("id", self._ping.id),
            ("hostname", self._ping.hostname),
            ("query", self._ping.query),
            ("replies", [x.id for x in self._ping.replies]),
            ("resolver_address", self._ping.resolver_address),
            ("t", self._ping.t),
        ])

    def step_id(self) -> int:
        return self._step_id

    def id(self) -> int:
        return self._ping.id

    def kind(self) -> Kind:
        return Kind.DNS_SINGLE_PING_RESULT

    def origin(self) -> Origin:
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._ping.raw

    def unwrap(self) -> Any:
        return self._ping


class MeasurementDB:
    """Wraps a measurement providing DB-like access."""

    def __init__(self, meas: WebstepsTestKeys):
        self._meas = meas
        self._table: Dict[int, Entry] = {}
        self._load(meas)

    def tabular(self) -> Tabular:
        """Converts to tabular format."""
        return Tabular.create([
            ("url", self.url()),
            ("tags", self.tags()),
        ])

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this database."""
        return self._meas.raw

    def tags(self) -> List[str]:
        """Returns the measurement tags."""
        return self._meas.flags.tags()

    def url(self) -> str:
        """Returns the measurement URL."""
        return self._meas.url

    def list_analysis(self, url_idx: Optional[int] = None) -> List[Entry]:
        """Returns all the analysis entries."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() != Kind.ANALYSIS:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_dns(self, url_idx: Optional[int]) -> List[Entry]:
        """Returns all the dns entries."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() != Kind.DNS:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_endpoint(self, url_idx: Optional[int]) -> List[Entry]:
        """Returns all the endpoint entries."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() != Kind.ENDPOINT:
                continue
            if url_idx is not None and entry.step_id() != url_idx:
                continue
            out.append(entry)
        return out

    def list_urls(self) -> List[Entry]:
        """Returns the list of URLs measured in this measurement."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() == Kind.URL:
                out.append(entry)
        return out

    def find_entry(self, id: int) -> Entry:
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
        self._table[ssm.id] = URLMeasurementWrapper(ssm)
        for d in ssm.dns:
            self._load_dns(ssm.id, Origin.PROBE, d)
        for e in ssm.endpoint:
            self._load_endpoint(ssm.id, Origin.PROBE, e)

    def _load_th(self, step_id: int, th: Optional[WebstepsTHResponse]):
        if th is not None:
            for dns in th.dns:
                self._load_dns(step_id, Origin.TH, dns)
            for epnt in th.endpoint:
                self._load_endpoint(step_id, Origin.TH, epnt)

    def _load_dnsping(self, step_id: int, dnsping: Optional[DNSPingResult]):
        if dnsping is not None:
            for ping in dnsping.pings:
                self._table[ping.id] = DNSSinglePingResultWrapper(step_id, ping)
                for reply in ping.replies:
                    self._table[reply.id] = DNSSinglePingReplyWrapper(step_id, reply)

    def _load_probe_additional(self, step_id: int, epnts: List[MeasurexEndpointMeasurement]):
        for epnt in epnts:
            self._load_endpoint(step_id, Origin.PROBE, epnt)

    def _load_analysis(self, step_id: int, analysis: Optional[WebstepsAnalysis]):
        if analysis is not None:
            for dns in analysis.dns:
                self._table[dns.id] = AnalysisDNSOrEndpointWrapper(step_id, Origin.PROBE, dns)
            for epnt in analysis.endpoint:
                self._table[epnt.id] = AnalysisDNSOrEndpointWrapper(step_id, Origin.PROBE, epnt)

    def _load_dns(self, step_id: int, origin: Origin, dns: MeasurexDNSLookupMeasurement):
        self._table[dns.id] = DNSLookupMeasurementWrapper(step_id, origin, dns)

    def _load_endpoint(self, step_id: int, origin: Origin, epnt: MeasurexEndpointMeasurement):
        self._table[epnt.id] = EndpointMeasurementWrapper(step_id, origin, epnt)
