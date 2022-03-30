"""
Contains wrappers for probe-cli's internal/measurex package.

See internal/measurex/*.go
"""

from __future__ import annotations
from urllib.parse import urlunparse

from .typecast import (
    DictWrapper,
    IntWrapper,
    StrWrapper,
)

from .pkg_archival import (
    ArchivalDNSLookupResult,
    ArchivalHTTPRequestResult,
    ArchivalNetworkEvent,
    ArchivalTLSOrQUICHandshakeResult,
    ArchivalTCPConnectResult,
    FlatDNSLookupEvent,
    FlatDNSRoundTripEvent,
    FlatHTTPRoundTripEvent,
    FlatNetworkEvent,
    FlatQUICTLSHandshake,
)


class MeasurexSimpleURL:
    """Corresponds to internal/measurex.SimpleURL."""

    def __init__(self, data: DictWrapper):
        self.scheme = data.getstring("Scheme")
        self.host = data.getstring("Host")
        self.path = data.getstring("Path")
        self.raw_query = data.getstring("RawQuery")

    def __str__(self):
        return urlunparse((self.scheme, self.host, self.path, "", self.raw_query, ""))


class MeasurexCookie:
    """Corresponds to net/http.Cookie."""

    def __init__(self, data: DictWrapper):
        self.name = data.getstring("Name")
        self.value = data.getstring("Value")
        self.path = data.getstring("Path")
        self.domain = data.getstring("Domain")
        self.expires = data.getstring("Expires")
        self.max_age = data.getstring("MaxAge")
        self.secure = data.getstring("Secure")
        self.http_only = data.getbool("HttpOnly")
        self.same_site = data.getinteger("SameSite")


class MeasurexDNSLookupMeasurement:
    """Corresponds to internal/measurex.DNSLookupMeasurement."""

    def __init__(self, data: DictWrapper):
        self.id = data.getinteger("ID")
        self.lookup = FlatDNSLookupEvent(data.getdictionary("Lookup"))
        self.reverse_address = data.getstring("reverse_address")
        self.round_trip = [
            FlatDNSRoundTripEvent(DictWrapper(x)) for x in data.getlist("RoundTrip")
        ]


class MeasurexEndpointMeasurement:
    """Corresponds to internal/measurex.EndpointMeasurement."""

    def __init__(self, data: DictWrapper, include_body: bool):
        self.id = data.getinteger("ID")
        self.url = MeasurexSimpleURL(data.getdictionary("URL"))
        self.network = data.getstring("Network")
        self.address = data.getstring("Address")
        self.options = data.getdictionary("Options").unwrap()
        self.orig_cookies = [
            MeasurexCookie(DictWrapper(x)) for x in data.getlist("OrigCookies")
        ]
        self.failure = data.getstring("Failure")
        self.failed_operation = data.getstring("FailedOperation")
        self.new_cookies = [
            MeasurexCookie(DictWrapper(x)) for x in data.getlist("NewCookies")
        ]
        self.location = MeasurexSimpleURL(data.getdictionary("Location"))
        self.http_title = data.getstring("HTTPTitle")
        self.network_event = [
            FlatNetworkEvent(DictWrapper(x)) for x in data.getlist("NetworkEvent")
        ]
        self.tcp_connect = FlatNetworkEvent(data.getdictionary("TCPConnect"))
        self.quic_tls_handshake = FlatQUICTLSHandshake(
            data.getdictionary("QUICTLSHandshake")
        )
        self.http_round_trip = FlatHTTPRoundTripEvent(
            data.getdictionary("HTTPRoundTrip"), include_body
        )

    def status_code(self) -> int:
        return self.http_round_trip.status_code

    def response_body_length(self) -> int:
        return self.http_round_trip.response_body_length


class MeasurexArchivalDNSLookupMeasurement:
    """Corresponds to internal/measurex.ArchivalDNSLookupMeasurement."""

    def __init__(self, entry: DictWrapper):
        self.id = entry.getinteger("id")
        self.domain = entry.getstring("domain")
        self.reverse_address = entry.getstring("reverse_address")
        self.resolver_network = entry.getstring("resolver_network")
        self.resolver_address = entry.getstring("resolver_address")
        self.failure = entry.getfailure("failure")
        self.addresses = [StrWrapper(x).unwrap() for x in entry.getlist("addresses")]
        self.queries = [
            ArchivalDNSLookupResult(DictWrapper(x)) for x in entry.getlist("queries")
        ]
        self.raw = entry.unwrap()


class MeasurexArchivalEndpointMeasurement:
    """Corresponds to internal/measurex.ArchivalEndpointMeasurement."""

    def __init__(self, entry: DictWrapper):
        self.id = entry.getinteger("id")
        self.url = entry.getstring("url")
        self.network = entry.getstring("network")
        self.address = entry.getstring("address")
        self.cookies_names = [
            StrWrapper(x).unwrap() for x in entry.getlist("cookies_names")
        ]
        self.failure = entry.getfailure("failure")
        self.failed_operation = entry.getfailure("failed_operation")
        self.status_code = entry.getinteger("status_code")
        self.location = entry.getstring("location")
        self.body_length = entry.getinteger("body_length")
        self.title = entry.getstring("title")
        self.network_events = [
            ArchivalNetworkEvent(DictWrapper(x))
            for x in entry.getlist("network_events")
        ]
        self.tcp_connect = ArchivalTCPConnectResult.optional(
            entry.getdictionary("tcp_connect")
        )
        self.quic_tls_handshake = ArchivalTLSOrQUICHandshakeResult.optional(
            entry.getdictionary("quic_tls_handshake")
        )
        self.request = ArchivalHTTPRequestResult(entry.getdictionary("request"))
        self.raw = entry.unwrap()


class MeasurexArchivalURLMeasurement:
    """Corresponds to internal/measurex.ArchivalURLMeasurement."""

    def __init__(self, entry: DictWrapper):
        self.id = entry.getinteger("id")
        self.endpoint_ids = [
            IntWrapper(x).unwrap() for x in entry.getlist("endpoint_ids")
        ]
        self.url = entry.getstring("url")
        self.cookies = [StrWrapper(x).unwrap() for x in entry.getlist("cookies")]
        self.dns = [
            MeasurexArchivalDNSLookupMeasurement(DictWrapper(x))
            for x in entry.getlist("dns")
        ]
        self.endpoint = [
            MeasurexArchivalEndpointMeasurement(DictWrapper(x))
            for x in entry.getlist("endpoint")
        ]
        self.raw = entry.unwrap()
