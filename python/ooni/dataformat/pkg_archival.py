"""
Contains wrappers for probe-cli's internal/archival package.

See internal/archival/{archival,flat}.go and internal/model/archival.go.
"""


from __future__ import annotations
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)
from urllib.parse import urlunparse

from .typecast import (
    DictWrapper,
    StrWrapper,
)

#
# Archival
#
# Corresponds to code in internal/model/archival.go and
# internal/archival/archival.go
#


class ArchivalBinaryData:
    """Corresponds to internal/model.ArchivalBinaryData."""

    def __init__(self, entry: DictWrapper):
        self.format = entry.getstring("format")
        self.data = entry.getstring("data")
        self.raw = entry.unwrap()

    @staticmethod
    def optional(value: DictWrapper) -> Optional[ArchivalBinaryData]:
        if not value:
            return None
        return ArchivalBinaryData(value)


class ArchivalDNSAnswer:
    """Corresponds to internal/model.ArchivalDNSAnswer."""

    def __init__(self, entry: DictWrapper):
        self.alpn = entry.getstring("alpn")
        self.asn = entry.getinteger("asn")
        self.as_org_name = entry.getstring("asn_org_name")
        self.answer_type = entry.getstring("answer_type")
        self.hostname = entry.getstring("hostname")
        self.ipv4 = entry.getstring("ipv4")
        self.ipv6 = entry.getstring("ipv6")
        self.ns = entry.getstring("ns")
        self.ttl = entry.getinteger("ttl")


class ArchivalDNSLookupResult:
    """Corresponds to internal/model.ArchivalDNSLookupResult."""

    def __init__(self, entry: DictWrapper):
        self.answers = [
            ArchivalDNSAnswer(DictWrapper(x)) for x in entry.getlist("answers")
        ]
        self.engine = entry.getstring("engine")
        self.failure = entry.getfailure("failure")
        self.hostname = entry.getstring("hostname")
        self.query_type = entry.getstring("query_type")
        self.raw_query = ArchivalBinaryData.optional(entry.getdictionary("raw_query"))
        self.raw_reply = ArchivalBinaryData.optional(entry.getdictionary("raw_reply"))
        self.resolver_hostname = None
        self.resolver_port = None
        self.resolver_address = entry.getstring("resolver_address")
        self.started = entry.getfloat("started")
        self.t = entry.getfloat("t")

    def resolver_url(self) -> str:
        return resolver_url(self.engine, self.resolver_address)


class ArchivalNetworkEvent:
    """Corresponds to internal/model.ArchivalNetworkEvent."""

    def __init__(self, entry: DictWrapper):
        self.address = entry.getstring("address")
        self.failure = entry.getfailure("failure")
        self.num_bytes = entry.getinteger("num_bytes")
        self.operation = entry.getstring("operation")
        self.proto = entry.getstring("proto")
        self.started = entry.getfloat("started")
        self.t = entry.getfloat("t")
        self.tags = [StrWrapper(x).unwrap() for x in entry.getlist("tags")]


class ArchivalTCPConnectStatus:
    """Corresponds to internal/model.ArchivalTCPConnectStatus."""

    def __init__(self, entry: DictWrapper):
        self.blocked = entry.getoptionalbool("blocked")
        self.failure = entry.getfailure("failure")
        self.success = entry.getbool("success")


class ArchivalTCPConnectResult:
    """Corresponds to internal/model.ArchivalTCPConnectResult."""

    def __init__(self, entry: DictWrapper):
        self.ip = entry.getstring("ip")
        self.port = entry.getinteger("port")
        self.status = ArchivalTCPConnectStatus(entry.getdictionary("status"))
        self.started = entry.getfloat("started")
        self.t = entry.getfloat("t")

    @staticmethod
    def optional(entry: DictWrapper) -> Optional[ArchivalTCPConnectResult]:
        if not entry:
            return None
        return ArchivalTCPConnectResult(entry)


class ArchivalTLSOrQUICHandshakeResult:
    """Corresponders to internal/model.TLSOrQUICHandshakeResult."""

    def __init__(self, entry: DictWrapper):
        self.address = entry.getstring("address")
        self.cipher_suite = entry.getstring("cipher_suite")
        self.failure = entry.getfailure("failure")
        self.negotiated_protocol = entry.getstring("negotiated_protocol")
        self.no_tls_verify = entry.getbool("no_tls_verify")
        self.peer_certificates = [
            ArchivalBinaryData(DictWrapper(x))
            for x in entry.getlist("peer_certificates")
        ]
        self.proto = entry.getstring("proto")
        self.server_name = entry.getstring("server_name")
        self.started = entry.getfloat("started")
        self.t = entry.getfloat("t")
        self.tags = [StrWrapper(x).unwrap() for x in entry.getlist("tags")]
        self.tls_version = entry.getstring("tls_version")

    @staticmethod
    def optional(entry: DictWrapper) -> Optional[ArchivalTLSOrQUICHandshakeResult]:
        if not entry:
            return None
        return ArchivalTLSOrQUICHandshakeResult(entry)


class ArchivalMaybeBinaryData:
    """Corresponds to internal/model.ArchivalMaybeBinaryData."""

    def __init__(self, value: Any):
        if isinstance(value, str):
            self._format = "identity"
            self._value = value
        elif isinstance(value, dict):
            value = DictWrapper(value)
            self._format = value.getstring("format")
            self._value = value.getstring("value")
        else:
            raise ValueError(f"unexpected type for ArchivalMaybeBinaryData: {value}")

    def is_utf8(self) -> bool:
        return self._format == "identity"

    def format(self) -> str:
        return self._format

    def value(self) -> str:
        return self._value

    @staticmethod
    def optional(value: Any) -> Optional[ArchivalMaybeBinaryData]:
        if value is None:
            return None
        return ArchivalMaybeBinaryData(value)


class ArchivalHTTPTor:
    """Corresponds to internal/model.ArchivalHTTPTor."""

    def __init__(self, entry: DictWrapper):
        self.exit_ip = entry.getoptionalstring("exit_ip")
        self.exit_name = entry.getoptionalstring("exit_name")
        self.is_tor = entry.getbool("is_tor")


def _archival_http_headers_list(
    values: List,
) -> List[Tuple[str, ArchivalMaybeBinaryData]]:
    """Converts a generic list in a list of HTTP headers."""
    out: List[Tuple[str, ArchivalMaybeBinaryData]] = []
    for elem in values:
        if len(elem) != 2:
            continue  # we expect key, value pairs
        key = StrWrapper(elem[0]).unwrap()
        value = ArchivalMaybeBinaryData(elem[1])
        out.append((key, value))
    return out


def _archival_http_headers_map(
    values: DictWrapper,
) -> Dict[str, ArchivalMaybeBinaryData]:
    """Converts a dict with headers to the map headers representation."""
    out: Dict[str, ArchivalMaybeBinaryData] = {}
    for key, value in values.unwrap().items():
        key = StrWrapper(key).unwrap()
        value = ArchivalMaybeBinaryData(value)
        out[key] = value
    return out


class ArchivalHTTPRequest:
    """Corresponds to internal/model.ArchivalHTTPRequest."""

    def __init__(self, entry: DictWrapper):
        self.body = ArchivalMaybeBinaryData.optional(entry.getany("body"))
        self.body_is_truncated = entry.getbool("body_is_truncated")
        self.headers_list = _archival_http_headers_list(entry.getlist("headers_list"))
        self.headers = _archival_http_headers_map(entry.getdictionary("headers"))
        self.method = entry.getstring("method")
        self.tor = ArchivalHTTPTor(entry.getdictionary("tor"))
        self.transport = entry.getstring("x_transport")
        self.url = entry.getstring("url")


class ArchivalHTTPResponse:
    """Corresponds to internal/model.ArchivalHTTPResponse."""

    def __init__(self, entry: DictWrapper):
        self.body = ArchivalMaybeBinaryData.optional(entry.getany("body"))
        self.body_length = entry.getinteger("body_length")
        self.body_is_truncated = entry.getinteger("body_is_truncated")
        self.body_tlsh = entry.getstring("body_tlsh")
        self.code = entry.getinteger("code")
        self.headers_list = _archival_http_headers_list(entry.getlist("headers_list"))
        self.headers = _archival_http_headers_map(entry.getdictionary("headers"))


class ArchivalHTTPRequestResult:
    """Corresponds to internal/model.ArchivalHTTPRequestResult"""

    def __init__(self, entry: DictWrapper):
        self.failure = entry.getfailure("failure")
        self.request = ArchivalHTTPRequest(entry.getdictionary("request"))
        self.response = ArchivalHTTPResponse(entry.getdictionary("response"))
        self.started = entry.getfloat("started")
        self.t = entry.getfloat("t")


#
# Flat
#
# Corresponds to internal/archival/flat.go
#


class FlatDNSRoundTripEvent:
    """Corresponds to internal/archival.FlatDNSRoundTripEvent."""

    def __init__(self, data: DictWrapper):
        self.failure = data.getstring("Failure")
        self.finished = data.getstring("Finished")
        self.query = data.getstring("Query")
        self.reply = data.getstring("Reply")
        self.resolver_address = data.getstring("ResolverAddress")
        self.resolver_network = data.getstring("ResolverNetwork")
        self.started = data.getstring("Started")


def resolver_url(network: str, address: str) -> str:
    """Returns the resolver URL given a resolver network and address."""
    if network == "doh":
        return address
    return urlunparse((network, address, "/", "", "", ""))


class FlatDNSLookupEvent:
    """Corresponds to internal/archival.FlatDNSLookupEvent."""

    def __init__(self, data: DictWrapper):
        self.alpns = [StrWrapper(x).unwrap() for x in data.getlist("ALPNs")]
        self.addresses = [StrWrapper(x).unwrap() for x in data.getlist("Addresses")]
        self.cname = data.getstring("CNAME")
        self.domain = data.getstring("Domain")
        self.failure = data.getstring("Failure")
        self.finished = data.getstring("Finished")
        self.lookup_type = data.getstring("LookupType")
        self.ns = [StrWrapper(x).unwrap() for x in data.getlist("NS")]
        self.ptr = [StrWrapper(x).unwrap() for x in data.getlist("PTRs")]
        self.resolver_address = data.getstring("ResolverAddress")
        self.resolver_network = data.getstring("ResolverNetwork")
        self.started = data.getstring("Started")

    def resolver_url(self) -> str:
        return resolver_url(self.resolver_network, self.resolver_address)


class FlatNetworkEvent:
    """Correspondes to internal/archival.FlatNetworkEvent."""

    def __init__(self, data: DictWrapper):
        self.count = data.getinteger("Count")
        self.failure = data.getstring("Failure")
        self.finished = data.getstring("Finished")
        self.network = data.getstring("Network")
        self.operation = data.getstring("Operation")
        self.remote_addr = data.getstring("RemoteAddr")
        self.started = data.getstring("Started")


class FlatQUICTLSHandshake:
    """Corresponds to internal/archival.FlatQUICTLSHandshake."""

    def __init__(self, data: DictWrapper):
        self.alpn = [StrWrapper(x) for x in data.getlist("ALPN")]
        self.cipher_suite = data.getstring("CipherSuite")
        self.failure = data.getstring("Failure")
        self.finished = data.getstring("Finished")
        self.negotiated_proto = data.getstring("NegotiatedProto")
        self.network = data.getstring("Network")
        self.peer_certs = [StrWrapper(x) for x in data.getlist("PeerCerts")]
        self.remote_addr = data.getstring("RemoteAddr")
        self.sni = data.getstring("SNI")
        self.skip_verify = data.getbool("SkipVerify")
        self.started = data.getstring("Started")
        self.tls_version = data.getstring("TLSVersion")


class FlatHTTPHeader:
    """Corresponds to net/http.Header."""

    def __init__(self, data: DictWrapper):
        self.headers: Dict[str, List[str]] = {}
        for key, values in data.unwrap().items():
            key = StrWrapper(key).unwrap()
            newvalues: List[str] = []
            for value in values:
                newvalues.append(StrWrapper(value).unwrap())
            self.headers[key] = newvalues


class FlatHTTPRoundTripEvent:
    """Correspondes to internal/archival.FlatHTTPRoundTripEvent."""

    def __init__(self, data: DictWrapper, include_body):
        self.failure = data.getstring("Failure")
        self.finished = data.getstring("Finished")
        self.method = data.getstring("Method")
        self.request_headers = FlatHTTPHeader(data.getdictionary("RequestHeaders"))
        self.response_body = data.getstring("ResponseBody") if include_body else ""
        self.response_body_is_truncated = data.getbool("ResponseBodyIsTruncated")
        self.response_body_length = data.getinteger("ResponseBodyLength")
        self.response_body_tlsh = data.getstring("ResponseBodyTLSH")
        self.response_headers = FlatHTTPHeader(data.getdictionary("ResponseHeaders"))
        self.started = data.getstring("Started")
        self.status_code = data.getinteger("StatusCode")
        self.transport = data.getstring("Transport")
        self.url = data.getstring("URL")
