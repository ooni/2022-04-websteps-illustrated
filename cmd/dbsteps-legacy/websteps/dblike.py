"""Database-like abstraction over websteps measurements."""

from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Protocol

from .websteps import Analysis
from .websteps import AnalysisDNSOrEndpoint
from .websteps import DNSLookupMeasurement
from .websteps import DNSPing
from .websteps import DNSSinglePingReply
from .websteps import DNSSinglePingResult
from .websteps import EndpointMeasurement
from .websteps import Measurement
from .websteps import THResponse
from .websteps import URLMeasurement


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

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {}

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


class GettableEntryID(Protocol):
    """Protocol representing anything with an entry_id method."""

    def entry_id(self) -> int:
        """Returns the ID of this entry."""
        return 0


def _reduce_to_ids(source: List[GettableEntryID]) -> List[int]:
    out: List[int] = []
    for entry in source:
        out.append(entry.entry_id())
    return out


class URLMeasurementWrapper:
    """Wrapper for URLMeasurement."""

    def __init__(self, um: URLMeasurement):
        self._um = um

    def dict(self) -> Dict[str, Any]:
        return {
            "id": self._um.id,
            "endpoint_ids": self._um.endpoint_ids,
            "url": self._um.url,
            "cookies": self._um.cookies,
            "dns": _reduce_to_ids(self._um.dns),
            "endpoint": _reduce_to_ids(self._um.endpoint),
        }

    def id(self) -> int:
        return self._um.id

    def kind(self) -> Kind:
        return Kind.URL

    def origin(self) -> Origin:
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        return self._um.raw

    def unwrap(self) -> Any:
        return self._um


class DNSLookupMeasurementWrapper:
    """Wrapper for a DNSLookupMeasurement."""

    def __init__(self, origin: Origin, dns: DNSLookupMeasurement):
        self._dns = dns
        self._origin = origin

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {
            "id": self._dns.id,
            "url_measurement_id": self._dns.url_measurement_id,
            "domain": self._dns.domain,
            "failure": self._dns.failure,
            "addresses": self._dns.addresses,
            "alpns": self._dns.alpns,
        }

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return self._dns.id

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.DNS

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return self._origin

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return self._dns.raw

    def unwrap(self) -> Any:
        return self._dns


class EndpointMeasurementWrapper:
    """Wrapper for and EndpointMeasurement."""

    def __init__(self, origin: Origin, epnt: EndpointMeasurement):
        self._epnt = epnt
        self._origin = origin

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {
            "id": self._epnt.id,
            "url_measurement_id": self._epnt.url_measurement_id,
            "url": self._epnt.url,
            "endpoint": self._epnt.endpoint,
            "failure": self._epnt.failure,
            "failed_operation": self._epnt.failed_operation,
        }

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return self._epnt.id

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.ENDPOINT

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return self._origin

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return self._epnt.raw

    def unwrap(self) -> Any:
        return self._epnt


class AnalysisDNSOrEndpointWrapper:
    """Wrapper for Analysis."""

    def __init__(self, origin: Origin, analysis: AnalysisDNSOrEndpoint):
        self._analysis = analysis
        self._origin = origin

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {
            "id": self._analysis.id,
            "url_measurement_id": self._analysis.url_measurement_id,
            "refs": self._analysis.refs,
            "flags": self._analysis.flags.tags(),
        }

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return self._analysis.id

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.ANALYSIS

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return self._origin

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return self._analysis.raw

    def unwrap(self) -> Any:
        return self._analysis


class DNSSinglePingReplyWrapper:
    """Wrapper for DNSSinglePingResult."""

    def __init__(self, reply: DNSSinglePingReply):
        self._reply = reply

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {
            "addresses": self._reply.addresses,
            "alpns": self._reply.alpns,
            "failure": self._reply.failure,
            "id": self._reply.id,
            "query_id": self._reply.query_id,
            "reply": self._reply.reply,
            "source_address": self._reply.source_address,
            "t": self._reply.t,
        }

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return self._reply.id

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.DNS_SINGLE_PING_REPLY

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return self._reply.raw

    def unwrap(self) -> Any:
        return self._reply


class DNSSinglePingResultWrapper:
    """Wrapper for DNSSinglePingResult."""

    def __init__(self, ping: DNSSinglePingResult):
        self._ping = ping

    def dict(self) -> Dict[str, Any]:
        """Converts this entry to a flat dictionary."""
        return {
            "hostname": self._ping.hostname,
            "id": self._ping.id,
            "query": self._ping.query,
            "replies": _reduce_to_ids(self._ping.replies),
            "resolver_address": self._ping.resolver_address,
            "t": self._ping.t,
        }

    def id(self) -> int:
        """Returns the unique ID of this entry."""
        return self._ping.id

    def kind(self) -> Kind:
        """Returns the kind of this entry."""
        return Kind.DNS_SINGLE_PING_RESULT

    def origin(self) -> Origin:
        """Returns the origin of this entry."""
        return Origin.PROBE

    def raw(self) -> Dict[str, Any]:
        """Returns the raw data that generated this entry."""
        return self._ping.raw

    def unwrap(self) -> Any:
        return self._ping


class MeasurementDB:
    """Wraps a measurement providing DB-like access."""

    def __init__(self, meas: Measurement):
        self._meas = meas
        self._table: Dict[int, Entry] = {}
        self._load(meas)

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
            analysis: AnalysisDNSOrEndpoint = entry.unwrap()
            if url_idx is not None and analysis.url_measurement_id != url_idx:
                continue
            out.append(entry)
        return out

    def list_dns(self, url_idx: Optional[int]) -> List[Entry]:
        """Returns all the dns entries."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() != Kind.DNS:
                continue
            dns: DNSLookupMeasurement = entry.unwrap()
            if url_idx is not None and dns.url_measurement_id != url_idx:
                continue
            out.append(entry)
        return out

    def list_endpoint(self, url_idx: Optional[int]) -> List[Entry]:
        """Returns all the endpoint entries."""
        out: List[Entry] = []
        for entry in self._table.values():
            if entry.kind() != Kind.ENDPOINT:
                continue
            epnt: EndpointMeasurement = entry.unwrap()
            if url_idx is not None and epnt.url_measurement_id != url_idx:
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

    def _load(self, meas: Measurement):
        for step in meas.steps:
            self._load_probe_initial(step.probe_initial)
            self._load_th(step.th)
            self._load_dnsping(step.dnsping)
            self._load_probe_additional(step.probe_additional)
            self._load_analysis(step.analysis)

    def _load_probe_initial(self, um: URLMeasurement):
        self._table[um.id] = URLMeasurementWrapper(um)
        for dns in um.dns:
            self._load_dns(Origin.PROBE, dns)
        for epnt in um.endpoint:
            self._load_endpoint(Origin.PROBE, epnt)

    def _load_th(self, th: Optional[THResponse]):
        if th is not None:
            for dns in th.dns:
                self._load_dns(Origin.TH, dns)
            for epnt in th.endpoint:
                self._load_endpoint(Origin.TH, epnt)

    def _load_dnsping(self, dnsping: Optional[DNSPing]):
        if dnsping is not None:
            for ping in dnsping.pings:
                self._table[ping.id] = DNSSinglePingResultWrapper(ping)
                for reply in ping.replies:
                    self._table[reply.id] = DNSSinglePingReplyWrapper(reply)

    def _load_probe_additional(self, epnts: List[EndpointMeasurement]):
        for epnt in epnts:
            self._load_endpoint(Origin.PROBE, epnt)

    def _load_analysis(self, analysis: Optional[Analysis]):
        if analysis is not None:
            for dns in analysis.dns:
                self._table[dns.id] = AnalysisDNSOrEndpointWrapper(Origin.PROBE, dns)
            for epnt in analysis.endpoint:
                self._table[epnt.id] = AnalysisDNSOrEndpointWrapper(Origin.PROBE, epnt)

    def _load_dns(self, origin: Origin, dns: DNSLookupMeasurement):
        self._table[dns.id] = DNSLookupMeasurementWrapper(origin, dns)

    def _load_endpoint(self, origin: Origin, epnt: EndpointMeasurement):
        self._table[epnt.id] = EndpointMeasurementWrapper(origin, epnt)
