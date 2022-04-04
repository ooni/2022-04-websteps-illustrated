"""Python library for managing websteps measurements."""

import base64
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


_FLAGS: List[Tuple[int, str]] = [
    (1 << 0, "#nxdomain"),
    (1 << 1, "#dnsTimeout"),
    (1 << 2, "#bogon"),
    (1 << 3, "#dnsNoAnswer"),
    (1 << 4, "#dnsRefused"),
    (1 << 6, "#dnsDiff"),
    (1 << 7, "#dnsServfail"),
    (1 << 15, "#dnsOther"),
    (1 << 16, "#tcpTimeout"),
    (1 << 17, "#tcpRefused"),
    (1 << 18, "#quicTimeout"),
    (1 << 19, "#tlsTimeout"),
    (1 << 20, "#tlsEOF"),
    (1 << 21, "#tlsReset"),
    (1 << 22, "#certificate"),
    (1 << 31, "#epntOther"),
    (1 << 33, "#httpTimeout"),
    (1 << 34, "#httpReset"),
    (1 << 35, "#httpEOF"),
    (1 << 36, "#httpDiffStatusCode"),
    (1 << 37, "#httpDiffHeaders"),
    (1 << 38, "#httpDiffTitle"),
    (1 << 39, "#httpDiffBodyLength"),
    (1 << 40, "#httpDiffBodyHash"),
    (1 << 47, "#httpOther"),
    (1 << 48, "#thFailure"),
]


class AnalysisFlags:
    """Wraps the analysis flags."""

    def __init__(self, flags: int):
        self.flags = flags

    def tags(self) -> List[str]:
        """Converts flags to a list of tags."""
        out: List[str] = []
        for flag in _FLAGS:
            if (self.flags & flag[0]) != 0:
                out.append(flag[1])
        return out


class AnalysisDNSOrEndpoint:
    """Results of the analysis of DNS or endpoint."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes an AnalysisDNSOrEndpoint from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.id: int = entry["id"]
        self.url_measurement_id: int = entry["url_measurement_id"]
        self.refs = self._load_refs(entry)
        self.flags: AnalysisFlags = AnalysisFlags(entry["flags"])
        self.raw = entry

    def entry_id(self) -> int:
        """Returns the ID of this entry."""
        return self.id

    @staticmethod
    def _load_refs(entry: Dict[str, Any]) -> List[int]:
        refs = entry["refs"]
        if refs is None:
            return []
        return refs


class Analysis:
    """Result of websteps analysis."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes an Analysis from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.dns = self._load_dns(entry)
        self.endpoint = self._load_endpoint(entry)
        self.raw = entry

    @staticmethod
    def _load_dns(entry: Dict[str, Any]) -> List[AnalysisDNSOrEndpoint]:
        dns = entry["dns"]
        if dns is None:
            return []
        out: List[AnalysisDNSOrEndpoint] = []
        for result in dns:
            out.append(AnalysisDNSOrEndpoint(result))
        return out

    @staticmethod
    def _load_endpoint(entry: Dict[str, Any]) -> List[AnalysisDNSOrEndpoint]:
        epnts = entry["endpoint"]
        if epnts is None:
            return []
        out: List[AnalysisDNSOrEndpoint] = []
        for result in epnts:
            out.append(AnalysisDNSOrEndpoint(result))
        return out


class DNSLookupMeasurement:
    """A DNS lookup measurement."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes a DNSLookupMeasurement from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.id: int = entry["id"]
        self.url_measurement_id = entry["url_measurement_id"]
        self.domain: str = entry["domain"]
        self.failure: Optional[str] = entry["failure"]
        self.addresses = self._load_addresses(entry)
        self.alpns = self._load_alpns(entry)
        self.raw = entry

    def entry_id(self) -> int:
        """Returns the ID of this entry."""
        return self.id

    @staticmethod
    def _load_addresses(entry: Dict[str, Any]) -> List[str]:
        addresses = entry["addresses"]
        if addresses is None:
            return []
        return addresses

    @staticmethod
    def _load_alpns(entry: Dict[str, Any]) -> List[str]:
        alpns = entry["alpns"]
        if alpns is None:
            return []
        return alpns


class EndpointMeasurement:
    """An endpoint measurement."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes an EndpointMeasurement from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.id: int = entry["id"]
        self.url_measurement_id: int = entry["url_measurement_id"]
        self.url: str = entry["url"]
        self.endpoint: str = entry["endpoint"]
        self.failure: Optional[str] = entry["failure"]
        self.failed_operation: Optional[str] = entry["failed_operation"]
        self.raw = entry

    def entry_id(self) -> int:
        """Returns the ID of this entry."""
        return self.id


def _load_dns(entry: Dict[str, Any]) -> List[DNSLookupMeasurement]:
    """Loads a DNSLookupMeasurement from a dictionary."""
    dns_list = entry["dns"]
    if dns_list is None:
        return []
    out: List[DNSLookupMeasurement] = []
    for dns in dns_list:
        out.append(DNSLookupMeasurement(dns))
    return out


def _load_endpoint(entry: Dict[str, Any]) -> List[EndpointMeasurement]:
    """Loads an EndpointMeasurement from a dictionary."""
    epnt_list = entry["endpoint"]
    if epnt_list is None:
        return []
    out: List[EndpointMeasurement] = []
    for epnt in epnt_list:
        out.append(EndpointMeasurement(epnt))
    return out


class URLMeasurement:
    """Measurement of an URL."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes an URLMeasurement from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.id: int = entry["id"]
        self.endpoint_ids = self._load_endpoint_ids(entry)
        self.url: str = entry["url"]
        self.cookies = self._load_cookies(entry)
        self.dns = _load_dns(entry)
        self.endpoint = _load_endpoint(entry)
        self.raw = entry

    @staticmethod
    def _load_endpoint_ids(entry: Dict[str, Any]) -> List[int]:
        ids = entry["endpoint_ids"]
        if ids is None:
            return []
        return ids

    @staticmethod
    def _load_cookies(entry: Dict[str, Any]) -> List[str]:
        cookies = entry["cookies"]
        if cookies is None:
            return []
        return cookies


class THResponse:
    """THResponse is the test helper's response."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes a THResponse from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.dns = _load_dns(entry)
        self.endpoint = _load_endpoint(entry)
        self.raw = entry


def _extract_binary_data(entry: Dict[str, str]) -> bytes:
    """Extractor for binary data fields."""
    if entry["format"] != "base64":
        raise ValueError("unknown binary data encoding")
    return base64.b64decode(entry["data"])


class DNSSinglePingReply:
    """DNSSinglePingReply contains a single reply to a DNSPing."""

    def __init__(self, entry: Dict[str, Any], query_id: int):
        """Initializes a DNSSinglePingReply from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.addresses = self._load_addresses(entry)
        self.alpns = self._load_alpns(entry)
        self.failure: Optional[str] = entry["failure"]
        self.id: int = entry["id"]
        self.query_id: int = query_id
        self.reply = _extract_binary_data(entry["reply"])
        self.source_address: str = entry["source_address"]
        self.t: int = entry["t"]
        self.raw = entry

    def entry_id(self) -> int:
        """Returns the ID of this entry."""
        return self.id

    def _load_addresses(self, entry: Dict[str, Any]) -> List[str]:
        addresses = entry["addresses"]
        if addresses is None:
            return []
        return addresses

    def _load_alpns(self, entry: Dict[str, Any]) -> List[str]:
        alpns = entry["alpns"]
        if alpns is None:
            return []
        return alpns


class DNSSinglePingResult:
    """DNSSinglePingResult contains a single entry of DNSPing."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes a DNSSinglePing from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.hostname: str = entry["hostname"]
        self.id: int = entry["id"]
        self.query = _extract_binary_data(entry["query"])
        self.resolver_address: str = entry["resolver_address"]
        self.t: float = entry["t"]
        self.replies = self._load_replies(entry, self.id)
        self.raw = entry

    @staticmethod
    def _load_replies(entry: Dict[str, Any], id: int) -> List[DNSSinglePingReply]:
        replies: Optional[List[Dict[str, Any]]] = entry["replies"]
        if replies is None:
            return []
        out: List[DNSSinglePingReply] = []
        for reply in replies:
            out.append(DNSSinglePingReply(reply, id))
        return out


class DNSPing:
    """DNSPing contains a dnsping measurement."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes a DNSPing from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.pings = self._load_single_ping(entry)
        self.raw = entry

    @staticmethod
    def _load_single_ping(entry: Dict[str, Any]) -> List[DNSSinglePingResult]:
        pings: Optional[List[Dict[str, Any]]] = entry["pings"]
        if pings is None:
            return []
        out: List[DNSSinglePingResult] = []
        for ping in pings:
            out.append(DNSSinglePingResult(ping))
        return out


class SingleStep:
    """A single step performed by websteps."""

    def __init__(self, entry: Dict[str, Any]):
        """Initializes a SingleStep from a dictionary. This function
        may throw exceptions if the test keys are not valid."""
        self.probe_initial = self._load_probe_initial(entry)
        self.th = self._load_th(entry)
        self.dnsping = self._load_dnsping(entry)
        self.probe_additional = self._load_probe_additional(entry)
        self.analysis = self._load_analysis(entry)
        self.flags: AnalysisFlags = AnalysisFlags(entry["flags"])

    @staticmethod
    def _load_probe_initial(entry: Dict[str, Any]) -> URLMeasurement:
        initial: Optional[Dict[str, Any]] = entry["probe_initial"]
        if initial is None:
            raise ValueError("Measurement where probe_initial is None")
        return URLMeasurement(initial)

    @staticmethod
    def _load_th(entry: Dict[str, Any]) -> Optional[THResponse]:
        th: Optional[Dict[str, Any]] = entry["th"]
        if th is None:
            return None
        return THResponse(th)

    @staticmethod
    def _load_dnsping(entry: Dict[str, Any]) -> Optional[DNSPing]:
        dnsping: Optional[Dict[str, Any]] = entry["dnsping"]
        if dnsping is None:
            return None
        return DNSPing(dnsping)

    @staticmethod
    def _load_probe_additional(entry: Dict[str, Any]) -> List[EndpointMeasurement]:
        additional: Optional[List[Dict[str, Any]]] = entry["probe_additional"]
        if additional is None:
            return []
        out: List[EndpointMeasurement] = []
        for elem in additional:
            out.append(EndpointMeasurement(elem))
        return out

    @staticmethod
    def _load_analysis(entry: Dict[str, Any]) -> Optional[Analysis]:
        analysis: Optional[Dict[str, Any]] = entry["analysis"]
        if analysis is None:
            return None
        return Analysis(analysis)


class Measurement:
    """A websteps measurement."""

    def __init__(self, testkeys: Dict[str, Any]):
        """Initializes a Measurement from the test keyes. This function
        may throw exceptions if the test keys are not valid."""
        self.flags: AnalysisFlags = AnalysisFlags(testkeys["flags"])
        self.url = str(testkeys["url"])
        self.steps = self._load_steps(testkeys)
        self.raw = testkeys

    def _load_steps(self, testkeys: Dict[str, Any]) -> List[SingleStep]:
        """Loads the steps of a given websteps measurement."""
        out: List[SingleStep] = []
        steps: List[Dict[str, Any]] = testkeys["steps"]
        for step in steps:
            out.append(SingleStep(step))
        return out


def _th_measurement_loader(measurement: Dict[str, Any]) -> Measurement:
    """Custom loader for TH measurements. These measurements are basically
    raw URLMeasurement instances. We need to refactor them so that the
    Measurement loader can load them successfully."""
    faketks: Dict[str, Any] = {
        "flags": 0,
        "url": "",
        "steps": [
            {
                "probe_initial": measurement,
                "th": None,
                "dnsping": None,
                "probe_additional": [],
                "analysis": None,
                "flags": 0,
            }
        ],
    }
    m = Measurement(faketks)
    m.url = measurement.get("url", "")
    return m


def _probe_measurement_loader(measurement: Dict[str, Any]) -> Measurement:
    """Custom loader for probe measurements. We just need to unwrap
    and use the test keys of the overall measurement."""
    return Measurement(measurement["test_keys"])


def load(measurement: Dict[str, Any], is_th: bool) -> Measurement:
    """This function loads a Measurement from a measurement dict parsed
    from the JSONL file. In case there is any error, this function throws
    a ValueError wrapping the original exception that occurred."""
    loader: Dict[bool, Any] = {
        True: _th_measurement_loader,
        False: _probe_measurement_loader,
    }
    try:
        meas = loader[is_th](measurement)
    except Exception as exc:
        raise ValueError("cannot parse measurement") from exc
    else:
        return meas
