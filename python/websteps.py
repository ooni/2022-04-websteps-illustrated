#!/usr/bin/env python3

"""
Websteps implementation written in Python.

Limitations:

1. header processing is case sensitive;

2. we definitely do not map all the errors that matter;

3. we should review how we handle cookies;

4. we do not perform any analysis;

5. we serialize results using the flat data format;

6. probably more limitations.

Anyway, the point of this client is to have a toy but ~conforming
implementation which is always good when writing a spec.

Also, an additional benefit of this implementation is that it's
just 2.5k LoC, so much easier to understand than the Go one.
"""

#
# Implementation note: this file should be a single file and should only
# depend on the standard library to keep this canonical client simple and
# independent of the need of installing software with `pip` which isn't
# always pratical on all the boxes where we run experiments.
#

from __future__ import annotations
import base64
import binascii
from collections import deque
import datetime

from enum import Enum
import errno
import http.client
import http.cookies
import io

import ipaddress
import json
import logging
import re
import socket
import ssl
from typing import (
    Any,
    Deque,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    OrderedDict,
    Tuple,
    TypeVar,
    Union,
)
from urllib.parse import urlsplit, urlunparse
from urllib.request import urlopen

logging.getLogger().setLevel(logging.INFO)

#
# Generics
#
# This layer contains generic code to help us with the implementation.
#


class Failure(Enum):
    """Represents a failure that occurred while measuring."""

    CONNECTION_REFUSED = "connection_refused"
    DNS_NXDOMAIN_ERROR = "dns_nxdomain_error"
    GENERIC_TIMEOUT_ERROR = "generic_timeout_error"
    HOST_UNREACHABLE = "host_unreachable"
    SSL_FAILED_HANDSHAKE = "ssl_failed_handshake"
    UNKNOWN_FAILURE = "unknown_failure"

    def __str__(self) -> str:
        return self.value


# Helper type to define a generic Result[T]
T = TypeVar("T")


class Result(Generic[T]):
    """Represents a result or a failure (like Rust's std::Result)."""

    def __init__(self, result: Optional[T], failure: Optional[Failure]):
        if result is None and failure is None:
            raise RuntimeError("both result and failure are None")
        if result is not None and failure is not None:
            raise RuntimeError("both failure and result are not None")
        self._result: Optional[T] = result
        self._failure: Optional[Failure] = failure

    def __str__(self) -> str:
        """Provides a convenient string representation for logging"""
        if self.is_err():
            return self.failure_string()
        return "ok"

    def unwrap(self) -> T:
        """Returns the wrapped type or throws if this result is a failure."""
        if self._failure is not None:
            raise RuntimeError(self._failure)
        if self._result is None:
            raise RuntimeError("inconsistent result object")
        return self._result

    def failure_string(self) -> str:
        """Returns the failure as a string or throws if this is a success."""
        if self._result is not None:
            raise RuntimeError("inconsistent result object")
        if self._failure is None:
            raise RuntimeError("failure is none")
        return str(self._failure)

    def is_err(self) -> bool:
        """Returns whether this result wraps an error."""
        return self._failure is not None

    def is_ok(self) -> bool:
        """Returns whether this result is OK."""
        return self._result is not None

    @staticmethod
    def from_failure(failure: Failure) -> Result:
        """Constructs a new ErrorOr from a failure."""
        return Result(None, failure)

    @staticmethod
    def from_result(value: T) -> Result:
        """Constructs a new ErrorOr from a result."""
        return Result(value, None)


def _json_marshal_type_expander(value: Any) -> Any:
    """Recursive worker function for the _json_marshal function."""
    #
    # TODO(bassosimone): consider where doing the following using a JSONEncoder
    # leads to less work or better code compared to this solution.
    #
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, Dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("keys must be strings")
            out[k] = _json_marshal_type_expander(v)
        return out
    if isinstance(value, list):
        out = []
        for entry in value:
            out.append(_json_marshal_type_expander(entry))
        return out
    if isinstance(value, HTTPHeader):
        return _json_marshal_type_expander(value.headers)
    if hasattr(value, "__dict__"):
        return _json_marshal_type_expander(value.__dict__)
    raise ValueError(f"_json_marshal_type_expander: cannot expand: {value}")


def _json_marshal(value: Any) -> str:
    """Custom JSON marshaller."""
    return json.dumps(_json_marshal_type_expander(value))


class HTTPHeader:
    """Represents HTTP headers.

    Equivalent to net/http.Header in the Go stdlib."""

    #
    # TODO(bassosimone): consider adding support for case
    # insensitive headers because using case sensitive will
    # definitely going to lead to weird results.
    #

    def __init__(self):
        self.headers: Dict[str, List[str]] = {}

    @staticmethod
    def unmarshal(m: Any) -> HTTPHeader:
        #
        # TODO(bassosimone): having to write custom unmarshallers
        # to have typed types is a bit frustrating and it may
        # probably be automated (or maybe there is a way to write
        # a function to do this in Python directly?)
        #
        msg = dict(m)
        o = HTTPHeader()
        for key, values in msg.items():
            key = str(key)
            values = [str(v) for v in values]
            o.headers[key] = values
        return o

    def clone(self) -> HTTPHeader:
        """Returns a clone of the original headers."""
        out = HTTPHeader()
        for key, values in self.headers.items():
            out.headers[key] = values[:]
        return out

    def append(self, key: str, value: str):
        """Appends the given header value to the values for the given key."""
        self.headers.setdefault(key, [])
        self.headers[key].append(value)

    @staticmethod
    def default() -> HTTPHeader:
        """Returns the default headers we use for measuring"""
        # Note: of course the following values (and especially the user-agent) will
        # eventually become older, but this is just an example client, so...
        out = HTTPHeader()
        out.headers = {
            "Accept": [
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ],
            "Accept-Language": [
                "en-US,en;q=0.9",
            ],
            "User-Agent": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            ],
        }
        return out


class HTTPCookie:
    """Represent a single HTTP cookie.

    Equivalent to net/http/measurex.Cookie in the Go stdlib."""

    # TODO(bassosimone): we found inconsistencies on how cookies are
    # actually represented insider the Go codebase:
    #
    # 1. secure should be bool (or, alternatively, all cookie values
    # should be strings probably?)
    #
    # 2. samesite is a actually a string but we think it's an
    # integer because Go internally uses an enum but I was
    # not fully aware of cookies' format so I didn't notice :facepalm:.
    #
    # We should fix this problem in the Go implementation and then
    # circle back to this implementation agaion.

    def __init__(self):
        self.Name = ""
        self.Value = ""
        self.Path = ""
        self.Domain = ""
        self.Expires = ""
        self.MaxAge = ""
        self.Secure = ""
        self.HTTPOnly = False
        self.SameSite = 0

    @staticmethod
    def unmarshal(m: Any) -> HTTPCookie:
        msg = dict(m)
        o = HTTPCookie()
        o.Name = msg.get("Name", "") or ""
        o.Value = msg.get("Value", "") or ""
        o.Path = msg.get("Path", "") or ""
        o.Domain = msg.get("Domain", "") or ""
        o.Expires = msg.get("Expires", "") or ""
        o.MaxAge = msg.get("MaxAge", "") or ""
        o.Secure = msg.get("Secure", "") or ""
        o.HTTPOnly = msg.get("HTTPOnly", False) or False
        o.SameSite = msg.get("SameSite", 0) or 0
        return o


#
# Networking
#
# This layer contains networking code.
#
# Our rough objective here is to have these fundamental operations:
#
# 1. DNS lookup using getaddrinfo
#
# 2. TCP connect to a remote endpoint
#
# 3. TLS handshake given a TCP conn and a SNI
#
# 4. HTTP GET given a URL and a conn
#
# The equivalent package in the Go implementation is internal/netxlite.
#
# Some functions in here mimic functionality in the Go stdlib that
# is nice to have when working with networking code.
#


def _join_address_port(address: str, port: str) -> str:
    """Takes in input an address and a port and joins them."""
    if _is_ipv6(address):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


class SplitAddressPortError(Exception):
    """Error when trying to split address and port."""


def _split_address_port(epnt: str) -> Tuple[str, int]:
    """Takes in input an endpoint like '8.8.8.8:443' or '[::1]:443' and
    emits in output the corresponding address and port. Raises ValueError
    in case epnt is not a valid endpoint."""
    purl = urlsplit("//" + epnt)
    if purl.hostname is None or purl.port is None:
        raise SplitAddressPortError(f"invalid endpoint: {epnt}")
    return purl.hostname, purl.port


def _is_loopback(addr: str) -> bool:
    """Returns true if addr is a loopback address."""
    try:
        ipaddr = ipaddress.ip_address(addr)
        return ipaddr.is_loopback
    except:
        return False


def _is_ip_addr(addr: str) -> bool:
    """Returns whether addr is an IP address."""
    try:
        ipaddress.ip_address(addr)
        return True
    except:
        return False


def _is_ipv6(addr: str) -> bool:
    """Returns whether if addr is an IPv6 address. Raises ValueError in
    case addr is not a valid IP address."""
    ip = ipaddress.ip_address(addr)
    return ip.version == 6


def _family_for_address(addr: str) -> int:
    """Returns the appropriate socket family for address. Raises ValueError
    in case addr is not a valid IP addr."""
    return socket.AF_INET6 if _is_ipv6(addr) else socket.AF_INET


def dns_lookup(domain: str) -> Result[List[str]]:
    """Performs a DNS lookup using the system resolver (i.e., getaddrinfo)."""
    try:
        # Note: the port here is completely irrelevant
        results = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        #
        # TODO(bassosimone): a full client should of course map more
        # error codes here but this is an example client, so...
        #
        if exc.args[0] == socket.EAI_NONAME:
            return Result.from_failure(Failure.DNS_NXDOMAIN_ERROR)
        else:
            return Result.from_failure(Failure.UNKNOWN_FAILURE)
    out: List[str] = []
    for _, _, _, _, addrport in results:
        out.append(addrport[0])
    return Result.from_result(out)


def tcp_connect(endpoint: str) -> Result[socket.socket]:
    """Connects to the given TCP endpoint. Raises OSError in case
    we cannot create a new socket."""
    addr, port = _split_address_port(endpoint)
    conn = socket.socket(_family_for_address(addr))
    conn.settimeout(15)  # Try to use the same default of ooniprobe
    try:
        conn.connect((addr, port))
    except OSError as exc:
        conn.close()  # We own the socket unless we return it
        if exc.args[0] == "timed out":
            return Result.from_failure(Failure.GENERIC_TIMEOUT_ERROR)
        if exc.errno == errno.ECONNREFUSED:
            return Result.from_failure(Failure.CONNECTION_REFUSED)
        if exc.errno == errno.EHOSTUNREACH:
            return Result.from_failure(Failure.HOST_UNREACHABLE)
        #
        # TODO(bassosimone): a serious client will of course map more
        # errors here. A serious client would also wrap the returned
        # socket to convert I/O errors to OONI errors.
        #
        logging.warning(f"tcp_connect: unhandled failure: {exc}")
        return Result.from_failure(Failure.UNKNOWN_FAILURE)
    else:
        return Result.from_result(conn)


def tls_handshake(
    conn: socket.socket, sni: str, alpns: List[str]
) -> Result[ssl.SSLSocket]:
    """Connects to a given TCP endpoint and performs a TLS handshake. Raises
    exceptions in case of failures independent of the measurement."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()
    ctx.set_alpn_protocols(alpns)
    ctx.check_hostname = True
    tlsconn = ctx.wrap_socket(conn, server_hostname=sni)
    #
    # TODO(bassosimone): a serious client should of course improve
    # the way in which we're handling errors here by more precisely
    # mapping the errors that occur to OONI errors.
    #
    try:
        tlsconn.do_handshake()
    except ssl.SSLCertVerificationError:
        return Result.from_failure(Failure.SSL_FAILED_HANDSHAKE)
    except OSError:
        return Result.from_failure(Failure.SSL_FAILED_HANDSHAKE)
    return Result.from_result(tlsconn)


class _HTTPEndpoint:
    """Converts an URL string to HTTP endpoint information suitable
    for "connecting" to a given endpoint using http.client."""

    def __init__(self, url: str):
        parsed = urlsplit(url)
        # We expect the hostname to be set because we expected the caller to
        # pass to this class a TCP endpoints, hence we raise an exception when
        # that's not the case. It's definitely a defect.
        if parsed.hostname is None:
            raise ValueError("hostname not set")
        self.netloc = parsed.netloc
        self.hostname = parsed.hostname
        self.port = parsed.port
        self.path = parsed.path


def _http_headers_to_dict(headers: HTTPHeader) -> Dict:
    """Converts our representation of HTTP headers to Python's one."""
    out = {}
    for key, values in headers.headers.items():
        if len(values) != 1:
            raise ValueError(
                "request headers cannot contain zero or multiple values per key"
            )
        out[key] = values[0]
    return out


def http_get(
    conn: Union[socket.socket, ssl.SSLSocket],
    url: str,
    headers: HTTPHeader,
) -> Result[http.client.HTTPResponse]:
    """Performs an HTTP GET using the given socket. We will use the path
    from the URL to issue the right request to the server. This func takes
    ownership of the conn and closes it when done."""
    epnt = _HTTPEndpoint(url)
    hc = http.client.HTTPConnection(epnt.hostname, epnt.port)
    hc.auto_open = 0
    hc.sock = conn  # transfer ownership to HTTPConnection
    pyhttpheaders = _http_headers_to_dict(headers)
    if "host" not in pyhttpheaders:
        pyhttpheaders["host"] = epnt.netloc
    #
    # TODO(bassosimone): of course for a simplistic client it's
    # perfectly okay to map errors in a sloppy way, though we
    # would need better error handling here to make this client
    # useful in general (which we probably don't want).
    #
    try:
        hc.request("GET", epnt.path, headers=pyhttpheaders)
    except:
        return Result.from_failure(Failure.UNKNOWN_FAILURE)
    try:
        hr = hc.getresponse()
    except:
        return Result.from_failure(Failure.UNKNOWN_FAILURE)
    else:
        return Result.from_result(hr)


#
# Flat
#
# This layer contains the flat dataformat and routines to fill
# the flat data format based on network measurements.
#
# The equivalent Go package is internal/archival and in
# particular the flat.go file inside it.
#
# Note to the reader: starting from here many structs do not
# follow PEP8 because we use the same naming as Go.
#


class FlatDNSLookupEvent:
    """Flat representation of a DNS lookup event.

    Corresponds to internal/archival.FlatDNSLookupEvent."""

    def __init__(self):
        self.ALPNs: List[str] = []
        self.Addresses: List[str] = []
        self.CNAME = ""
        self.Domain = ""
        self.Failure = ""
        self.Finished = ""
        self.LookupType = ""
        self.NS: List[str] = []
        self.PTR: List[str] = []
        self.ResolverAddress = ""
        self.ResolverNetwork = ""
        self.Started = ""

    @staticmethod
    def unmarshal(m: Any) -> FlatDNSLookupEvent:
        msg = dict(m)
        o = FlatDNSLookupEvent()
        o.ALPNs = [str(x) for x in msg.get("ALPNs", []) or []]
        o.Addresses = [str(x) for x in msg.get("Addresses", []) or []]
        o.CNAME = msg.get("CNAME", "") or ""
        o.Domain = msg.get("Domain", "") or ""
        o.Failure = msg.get("Failure", "") or ""
        o.Finished = msg.get("Finished", "") or ""
        o.LookupType = msg.get("LookupType", "") or ""
        o.NS = [str(x) for x in msg.get("NS", []) or []]
        o.PTR = [str(x) for x in msg.get("PTR", []) or []]
        o.ResolverAddress = msg.get("ResolverAddress", []) or []
        o.ResolverNetwork = msg.get("ResolverNetwork", "") or ""
        o.Started = msg.get("Started", "") or ""
        return o


class FlatNetworkEvent:
    """Flat representation of a network event (e.g., connect, read).

    Equivalent to internal/archival.FlatNetworkEvent."""

    def __init__(self):
        self.Count = 0
        self.Failure = ""
        self.Finished = ""
        self.Network = ""
        self.Operation = ""
        self.RemoteAddr = ""
        self.Started = ""

    @staticmethod
    def unmarshal(m: Any):
        msg = dict(m)
        o = FlatNetworkEvent()
        o.Count = msg.get("Count", 0) or 0
        o.Failure = msg.get("Failure", "") or ""
        o.Finished = msg.get("Finished", "") or ""
        o.Network = msg.get("Network", "") or ""
        o.Operation = msg.get("Operation", "") or ""
        o.RemoteAddr = msg.get("RemoteAddr", "") or ""
        o.Started = msg.get("Started", "") or ""
        return o


class FlatQUICTLSHandshake:
    """Flat representation of a QUIC or TLS handshake.

    Equivalent to internal/archival.FlatQUICTLSHandshake."""

    def __init__(self):
        self.ALPN: List[str] = []
        self.CipherSuite = ""
        self.Failure = ""
        self.Finished = ""
        self.NegotiatedProto = ""
        self.Network = ""
        self.PeerCerts: List[str] = []
        self.RemoteAddr = ""
        self.SNI: str = ""
        self.SkipVerify = False
        self.Started = ""
        self.TLSVersion = ""

    @staticmethod
    def unmarshal(m: Any) -> FlatQUICTLSHandshake:
        msg = dict(m)
        o = FlatQUICTLSHandshake()
        o.ALPN = [str(x) for x in msg.get("ALPN", []) or []]
        o.CipherSuite = msg.get("CipherSuite", "") or ""
        o.Failure = msg.get("Failure", "") or ""
        o.Finished = msg.get("Finished", "") or ""
        o.NegotiatedProto = msg.get("NegotiatedProto", "") or ""
        o.Network = msg.get("Network", "") or ""
        o.PeerCerts = [str(x) for x in msg.get("PeerCerts", []) or []]
        o.RemoteAddr = msg.get("RemoteAddr", "") or ""
        o.SNI = msg.get("SNI", "") or ""
        o.SkipVerify = msg.get("SkipVerify", False) or False
        o.Started = msg.get("Started", "") or ""
        o.TLSVersion = msg.get("TLSVersion", "") or ""
        return o


class FlatHTTPRoundTripEvent:
    """Flat representation of an HTTP round trip. Note that for OONI the
    round trip also includes reading a snapshot of the body.

    Equivalent to internal/archival.FlatHTTPRoundTripEvent."""

    def __init__(self):
        self.Failure = ""
        self.Finished = ""
        self.Method = ""
        self.RequestHeaders = HTTPHeader()
        self.ResponseBody = ""
        self.ResponseBodyIsTruncated = False
        self.ResponseBodyLength = 0
        self.ResponseBodyTLSH = ""
        self.ResponseHeaders = HTTPHeader()
        self.Started = ""
        self.StatusCode = 0
        self.Transport = ""
        self.URL: str = ""

    @staticmethod
    def unmarshal(m: Any) -> FlatHTTPRoundTripEvent:
        msg = dict(m)
        o = FlatHTTPRoundTripEvent()
        o.Failure = msg.get("Failure", "") or ""
        o.Finished = msg.get("Finished", "") or ""
        o.Method = msg.get("Method", "") or ""
        o.RequestHeaders = HTTPHeader.unmarshal(msg.get("RequestHeaders", {}) or {})
        o.ResponseBody = msg.get("ResponseBody", "") or ""
        o.ResponseBodyIsTruncated = msg.get("ResponseBodyIsTruncated", False) or False
        o.ResponseBodyLength = msg.get("ResponseBodyLength", 0) or 0
        o.ResponseBodyTLSH = msg.get("ResponseBodyTLSH", "") or ""
        o.ResponseHeaders = HTTPHeader.unmarshal(msg.get("ResponseHeaders", {}) or {})
        o.Started = msg.get("Started", "") or ""
        o.StatusCode = msg.get("StatusCode", 0) or 0
        o.Transport = msg.get("Transport", "") or ""
        o.URL = msg.get("URL", "") or ""
        return o


class FlatTrace:
    """A trace containing flat network measurements.

    Corresponds to internal/archival.Trace."""

    def __init__(self):
        self.dns_lookup: List[FlatDNSLookupEvent] = []
        self.quic_tls_handshake: List[FlatQUICTLSHandshake] = []
        self.http_round_trip: List[FlatHTTPRoundTripEvent] = []
        self.tcp_connect: List[FlatNetworkEvent] = []


def _time_now() -> str:
    """Formats the current UTC time like Go would format it."""
    # Example: 2022-03-31T01:38:57.287429956+08:00
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _new_endpoint(addr: Any) -> str:
    """Converts getsockname's or getpeername's result to an endpoint string."""
    ipaddr, port = addr[:2]
    if ipaddr.startswith("::ffff:"):  # Python seems to like emitting IPv6 mapped IPv4
        ipaddr = ipaddr[7:]
    if _is_ipv6(ipaddr):
        return f"[{ipaddr}]:{port}"
    return f"{ipaddr}:{port}"


def _peer_certs(cert: Any) -> List[str]:
    """Takes in input the result of getpeercert and returns in out
    a list of base64 encoded certificates."""
    return [base64.b64encode(cert).decode("utf-8")]


def _selected_alpn_protocol(proto: Any) -> str:
    """Returns the selected ALPN protocol as a possibly empty string."""
    if proto is None:
        return ""
    return str(proto)


def _http_headers_from_tuple(headers: List[Tuple[str, str]]) -> HTTPHeader:
    """Converts a tuple with headers to the flat format."""
    out = HTTPHeader()
    for key, value in headers:
        out.headers.setdefault(key, [])
        out.headers[key].append(value)
    return out


class _HTTPBodyReader:
    """Helps to read again the body after we've read it already."""

    #
    # There is a partial defect here that it seems we cannot just read a
    # chunk of the body and continue reading later. See below.
    #

    def __init__(self, data: bytes):
        self._data = io.BytesIO(data)

    def read(self, amt: Optional[int] = None) -> bytes:
        return self._data.read(amt)


class FlatSaver:
    """Saves measurement results organizing them into a Trace.

    Corresponds to internal/archival.Saver.
    """

    def __init__(self):
        self._trace = FlatTrace()

    def dns_lookup(self, domain: str) -> Result[List[str]]:
        """Performs a DNS lookup and saves the result into a trace."""
        event = FlatDNSLookupEvent()
        event.Domain = domain
        event.LookupType = "getaddrinfo"
        event.ResolverNetwork = "system"
        event.Started = _time_now()
        res = dns_lookup(domain)
        event.Finished = _time_now()
        if res.is_err():
            event.Failure = res.failure_string()
        else:
            event.Addresses = res.unwrap()
        self._trace.dns_lookup.append(event)
        return res

    def tcp_connect(self, endpoint: str) -> Result[socket.socket]:
        """Performs a TCP connect and saves the result into a trace."""
        event = FlatNetworkEvent()
        event.Network = "tcp"
        event.Operation = "connect"
        event.RemoteAddr = endpoint
        event.Started = _time_now()
        res = tcp_connect(endpoint)
        event.Finished = _time_now()
        if res.is_err():
            event.Failure = res.failure_string()
        self._trace.tcp_connect.append(event)
        return res

    def tls_handshake(
        self, conn: socket.socket, sni: str, alpns: List[str]
    ) -> Result[ssl.SSLSocket]:
        """Performs a TLS handshake and saves the result into a trace."""
        event = FlatQUICTLSHandshake()
        event.ALPN = alpns
        event.Network = "tcp"
        event.RemoteAddr = _new_endpoint(conn.getpeername())
        event.SNI = sni
        event.Started = _time_now()
        res = tls_handshake(conn, sni, alpns)
        event.Finished = _time_now()
        if res.is_err():
            event.Failure = res.failure_string()
        else:
            tlsconn = res.unwrap()
            cipher_suite, version = tlsconn.cipher()[:2]  # type: ignore
            event.CipherSuite = cipher_suite
            event.NegotiatedProto = _selected_alpn_protocol(
                tlsconn.selected_alpn_protocol()
            )
            #
            # TODO(bassosimone): apparently with Python we only get
            # the server's certificate, not the whole chain. So we
            # should perhaps document the PeerCerts field in the spec
            # repository to mention that the server's certificate is
            # mandatory and the rest of the chain isn't.
            #
            event.PeerCerts = _peer_certs(tlsconn.getpeercert(binary_form=True))
            event.TLSVersion = version
        self._trace.quic_tls_handshake.append(event)
        return res

    def http_get(
        self,
        conn: Union[socket.socket, ssl.SSLSocket],
        url: str,
        headers: HTTPHeader,
        body_snapshot_size=1 << 14,
    ) -> Result[http.client.HTTPResponse]:
        """Issues an HTTP GET request and saves results into a trace."""
        event = FlatHTTPRoundTripEvent()
        event.Method = "GET"
        event.RequestHeaders = headers
        event.Started = _time_now()
        event.URL = url
        event.Transport = "tcp"
        res = http_get(conn, url, headers)
        if res.is_err():
            event.Finished = _time_now()
            event.Failure = res.failure_string()
            self._trace.http_round_trip.append(event)
            return res
        resp = res.unwrap()
        event.StatusCode = resp.status
        event.ResponseHeaders = _http_headers_from_tuple(resp.getheaders())
        #
        # TODO(bassosimone): with Go we can read a snapshot of the body
        # and return to the caller allowing to re-read the snapshot plus
        # the remainder of the body. This is not possible here AFAICT.
        #
        # Because this is a toy client and I wanted to keep a design close
        # to the Go implementation, I chose to read the whole body and
        # take a snapshot of that while returning the whole body to the
        # caller so to allow reading again.
        #
        # Because in principle this whole snapshot thing is not necessary
        # for websteps but is there for OONI experiments using the
        # tracing approach, we could in principle avoid saving such a
        # snapshot here and do that inside measurex.
        #
        try:
            body = resp.read()
        except Exception:
            event.Finished = _time_now()
            event.Failure = str(Failure.UNKNOWN_FAILURE)
            self._trace.http_round_trip.append(event)
            return Result[http.client.HTTPResponse].from_failure(
                Failure.UNKNOWN_FAILURE
            )
        event.ResponseBody = base64.b64encode(body[:body_snapshot_size]).decode("utf-8")
        event.ResponseBodyLength = min(body_snapshot_size, len(body))
        event.ResponseBodyIsTruncated = len(body) > body_snapshot_size
        # Note: we're not computing the body's TLSH here
        event.Finished = _time_now()
        hbr = _HTTPBodyReader(body)
        resp.read = hbr.read
        self._trace.http_round_trip.append(event)
        return res

    def move_out_trace(self) -> FlatTrace:
        """Moves the internal trace out and replaces it with
        an new, empty trace for new measurements."""
        trace = self._trace
        self._trace = FlatTrace()
        return trace


#
# Measurex
#
# This layer contains measurement extensions. This code is the basic
# library that websteps requires for performing measurements.
#
# (In other words, everything below this line does not matter much
# as far as the websteps spec is concerned but is just support code
# that in a way or another needs to be there for measurex to
# exist: measurex is the first layer that the spec will mention.)
#
# Also: because the point of this client is to show algorithms in
# a compact way, I've tried to follow Go code AMAP.
#
# This code corresponds to internal/measurex.
#


class MeasurexIDGenerator:
    """Assigns a unique ID to each measurement.

    Corresponds to internal/measurex.IDGenerator."""

    def __init__(self):
        self._next = 0

    def next_id(self) -> int:
        self._next += 1
        return self._next


class MeasurexOptions:
    """Contains options for measurex.

    Corresponds to internal/measurex.Options."""

    #
    # Implementation note: this is a simplified version with
    # the bare minimum number of fields to interoperate.
    #
    # I think the spec should only mention these options as
    # mandatory as they seem the really core ones.
    #
    # Also, the Go implementation allows to stack options
    # because that is quite useful for the TH and also
    # to avoid mutating data structs. We don't care about
    # implementing a TH here and there are no races in
    # Python, so I avoided to add additional complexity.
    #

    def __init__(self):
        self.HTTPRequestHeaders = HTTPHeader.default()
        self.DoNotInitiallyForceHTTPAndHTTPS = False
        self.MaxAddressesPerFamily = 2
        self.MaxCrawlerDepth = 3
        # These are the main options that the TH will care about:
        self.MaxHTTPResponseBodySnapshotSize = 1 << 19
        self.MaxHTTPSResponseBodySnapshotSizeConnectivity = 1 << 12
        self.MaxHTTPSResponseBodySnapshotSizeThrottling = 1 << 19

    @staticmethod
    def unmarshal(m: Any) -> MeasurexOptions:
        msg = dict(m)
        o = MeasurexOptions()
        o.HTTPRequestHeaders = HTTPHeader.unmarshal(
            msg.get("HTTPRequestHeaders", {}) or {}
        )
        o.DoNotInitiallyForceHTTPAndHTTPS = (
            msg.get("DoNotInitiallyForceHTTPAndHTTPS", False) or False
        )
        o.MaxAddressesPerFamily = msg.get("MaxAddressesPerFamily", 0) or 0
        o.MaxCrawlerDepth = msg.get("MaxCrawlerDepth", 0) or 0
        o.MaxHTTPResponseBodySnapshotSize = (
            msg.get("MaxHTTPResponseBodySnapshotSize", 0) or 0
        )
        o.MaxHTTPSResponseBodySnapshotSizeConnectivity = (
            msg.get("MaxHTTPSResponseBodySnapshotSizeConnectivity", 0) or 0
        )
        o.MaxHTTPSResponseBodySnapshotSizeThrottling = (
            msg.get("MaxHTTPSResponseBodySnapshotSizeThrottling", 0) or 0
        )
        return o

    def clone(self) -> MeasurexOptions:
        """Returns a clone of the current options."""
        out = MeasurexOptions()
        out.HTTPRequestHeaders = self.HTTPRequestHeaders.clone()
        out.DoNotInitiallyForceHTTPAndHTTPS = self.DoNotInitiallyForceHTTPAndHTTPS
        out.MaxAddressesPerFamily = self.MaxAddressesPerFamily
        out.MaxCrawlerDepth = self.MaxCrawlerDepth
        out.MaxHTTPResponseBodySnapshotSize = self.MaxHTTPResponseBodySnapshotSize
        out.MaxHTTPSResponseBodySnapshotSizeConnectivity = (
            self.MaxHTTPSResponseBodySnapshotSizeConnectivity
        )
        out.MaxHTTPSResponseBodySnapshotSizeThrottling = (
            self.MaxHTTPSResponseBodySnapshotSizeThrottling
        )
        return out

    def clone_and_merge(self, other: MeasurexOptions) -> MeasurexOptions:
        """Clones the current options and merges them with the
        other options ensuring we only emit changes."""
        default = MeasurexOptions()
        out = self.clone()
        if other.HTTPRequestHeaders != default.HTTPRequestHeaders:
            out.HTTPRequestHeaders = other.HTTPRequestHeaders
        if (
            other.DoNotInitiallyForceHTTPAndHTTPS
            != default.DoNotInitiallyForceHTTPAndHTTPS
        ):
            out.DoNotInitiallyForceHTTPAndHTTPS = other.DoNotInitiallyForceHTTPAndHTTPS
        if other.MaxAddressesPerFamily != default.MaxAddressesPerFamily:
            out.MaxAddressesPerFamily = other.MaxAddressesPerFamily
        if other.MaxCrawlerDepth != default.MaxCrawlerDepth:
            out.MaxCrawlerDepth = other.MaxCrawlerDepth
        if (
            other.MaxHTTPResponseBodySnapshotSize
            != default.MaxHTTPResponseBodySnapshotSize
        ):
            out.MaxHTTPResponseBodySnapshotSize = other.MaxHTTPResponseBodySnapshotSize
        if (
            other.MaxHTTPSResponseBodySnapshotSizeConnectivity
            != default.MaxHTTPSResponseBodySnapshotSizeConnectivity
        ):
            out.MaxHTTPSResponseBodySnapshotSizeConnectivity = (
                other.MaxHTTPSResponseBodySnapshotSizeConnectivity
            )
        if (
            other.MaxHTTPSResponseBodySnapshotSizeThrottling
            != default.MaxHTTPSResponseBodySnapshotSizeThrottling
        ):
            out.MaxHTTPSResponseBodySnapshotSizeThrottling = (
                other.MaxHTTPSResponseBodySnapshotSizeThrottling
            )
        return out

    def snapsize_for_scheme_and_path(self, url: MeasurexSimpleURL) -> int:
        """Returs the correct body snapshot size for the given URL scheme and path.

        See the Go implementation or the spec for the rationale."""
        if url.Scheme == "http":
            return self.MaxHTTPResponseBodySnapshotSize
        if url.Scheme == "https" and url.Path not in ("", "/"):
            return self.MaxHTTPSResponseBodySnapshotSizeThrottling
        if url.Scheme == "https":
            return self.MaxHTTPSResponseBodySnapshotSizeConnectivity
        return 0


class MeasurexDNSResolverInfo:
    """Information on a resolver we want to use.

    Corresponds to internal/measurex.DNSResolverInfo."""

    def __init__(self):
        self.network = ""
        self.address = ""

    @staticmethod
    def system() -> MeasurexDNSResolverInfo:
        """Factory that creates a new system resolver."""
        out = MeasurexDNSResolverInfo()
        out.network = "system"
        out.address = ""
        return out


class MeasurexDNSLookupPlan:
    """Plan to perform a DNS lookup measurement.

    Corresponds to internal/measurex.DNSLookupPlan."""

    def __init__(self):
        self.url_measurement_id = 0
        self.domain = ""
        self.reverse_address = ""  # Note: we don't do reverse lookups here
        self.lookup_type = ""
        self.options = MeasurexOptions()
        self.resolver = MeasurexDNSResolverInfo()


class MeasurexDNSLookupMeasurement:
    """The result of a given DNSLookupPlan.

    Corresponds to internal/measurex.DNSLookupMeasurement."""

    def __init__(self):
        self.ID: int = 0
        self.URLMeasurementID = 0
        self.ReverseAddress = ""
        self.Lookup: Optional[FlatDNSLookupEvent] = None
        self.RoundTrip = []  # Note: we ignore DNS round trips here

    @staticmethod
    def unmarshal(m: Any) -> MeasurexDNSLookupMeasurement:
        msg = dict(m)
        o = MeasurexDNSLookupMeasurement()
        o.ID = msg.get("ID", 0) or 0
        o.URLMeasurementID = msg.get("URLMeasurementID", 0) or 0
        o.ReverseAddress = msg.get("ReverseAddress", "") or ""
        o.Lookup = FlatDNSLookupEvent.unmarshal(msg.get("Lookup", {}) or {})
        o.RoundTrip = []  # we are ignoring it
        return o

    def domain(self) -> str:
        """Returns the domain associated to this measurement."""
        if self.Lookup is None:
            return ""
        return self.Lookup.Domain

    def supports_http3(self) -> bool:
        """Returns whether this lookup measurement included ALPN hints."""
        # Note: this feature isn't implemented in Python
        return False

    def addresses(self) -> List[str]:
        """Returns the addresses resolved in this lookup."""
        if self.Lookup is None:
            return []
        return self.Lookup.Addresses

    def resolver_network(self) -> str:
        """Returns the network used by the resolver."""
        if self.Lookup is None:
            return ""
        return self.Lookup.ResolverNetwork


class MeasurexSimpleURL:
    """Simplified representation of a parsed URL. Only contains the
    fields we care about inside measurex and websteps.

    Equivalent to internal/measurex.SimpleURL."""

    def __init__(self):
        self.Scheme = ""
        self.Host = ""
        self.Path = ""
        self.RawQuery = ""  # follows go naming for net/url.URL

    @staticmethod
    def unmarshal(m: Any):
        msg = dict(m)
        o = MeasurexSimpleURL()
        o.Scheme = msg.get("Scheme", "") or ""
        o.Host = msg.get("Host", "") or ""
        o.Path = msg.get("Path", "") or ""
        o.RawQuery = msg.get("RawQuery", "") or ""
        return o

    def port(self) -> str:
        """Returns the port inside this URL."""
        try:
            _, port = _split_address_port(self.Host)
            return str(port)
        except:  # if we cannot parse host and port we assume there's no port
            if self.Scheme == "http":
                return "80"
            if self.Scheme == "https":
                return "443"
            raise RuntimeError(f"cannot determine port for {self.__dict__}")

    def clone_with_scheme(self, scheme: str) -> MeasurexSimpleURL:
        """Creates a clone of this URL with the given scheme."""
        out = MeasurexSimpleURL()
        out.Scheme = scheme
        out.Host = self.Host
        out.Path = self.Path
        out.RawQuery = self.RawQuery
        return out

    def clone(self) -> MeasurexSimpleURL:
        """Creates a clone of the current URL."""
        return self.clone_with_scheme(self.Scheme)

    @staticmethod
    def parse(url: str) -> MeasurexSimpleURL:
        """Parses the given input URL"""
        parsed = urlsplit(url)
        out = MeasurexSimpleURL()
        out.Scheme = parsed.scheme
        out.Host = parsed.netloc
        if out.Host == "":
            out.Host = "/"
        out.Path = parsed.path
        # TODO(bassosimone): is this the raw query?
        out.RawQuery = parsed.query
        return out

    def tostring(self) -> str:
        """Returns a string representation of this URL."""
        return urlunparse((self.Scheme, self.Host, self.Path, "", self.RawQuery, ""))

    def domain(self) -> str:
        """Returns the domain inside the hostname."""
        try:
            addr, _ = _split_address_port(self.Host)
            return addr
        except SplitAddressPortError:
            return self.Host


class MeasurexEndpointPlan:
    """Plan to measure an endpoint.

    Corresponds to internal/measurex.EndopointMeasurementPlan"""

    def __init__(self):
        self.url_measurement_id = 0
        self.domain = ""
        self.network = ""
        self.address = ""
        self.url: Optional[MeasurexSimpleURL] = None
        self.options = MeasurexOptions()
        self.cookies: List[HTTPCookie] = []


def _is_http_redirect(status_code: int) -> bool:
    """Returns whether this status code means there's a redirect."""
    return status_code in (301, 302, 303, 307, 308)


def _sorted_serialized_cookies_names(cookies: List[HTTPCookie]) -> List[str]:
    """Extracts only the cookies names and returns them sorted."""
    out: List[str] = []
    for cookie in cookies:
        out.append(cookie.Name)
    return sorted(out)


class MeasurexEndpointMeasurement:
    """Result of an endpoint measurement.

    Corresponds to internal/measurex.EndpointMeasurement"""

    def __init__(self):
        self.ID: int = 0
        self.URLMeasurementID = 0
        self.URL: Optional[MeasurexSimpleURL] = None
        self.Network = ""
        self.Address = ""
        self.Options = MeasurexOptions()
        self.OrigCookies: List[HTTPCookie] = []
        self.Finished = ""
        self.Failure = ""
        self.FailedOperation = ""
        self.NewCookies: List[HTTPCookie] = []
        self.Location: Optional[MeasurexSimpleURL] = None
        self.HTTPTitle = ""
        self.NetworkEvent = []  # we don't collect network events in this program
        self.TCPConnect: Optional[FlatNetworkEvent] = None
        self.QUICTLSHandshake: Optional[FlatQUICTLSHandshake] = None
        self.HTTPRoundTrip: Optional[FlatHTTPRoundTripEvent] = None

    @staticmethod
    def unmarshal(m: Any) -> MeasurexEndpointMeasurement:
        msg = dict(m)
        o = MeasurexEndpointMeasurement()
        o.ID = msg.get("ID", 0) or 0
        o.URLMeasurementID = msg.get("URLMeasurementID", 0) or 0
        o.URL = MeasurexSimpleURL.unmarshal(msg.get("URL", {} or {}))
        o.Network = msg.get("Network", "") or ""
        o.Address = msg.get("Address", "") or ""
        o.Options = MeasurexOptions.unmarshal(msg.get("Options", {}) or {})
        o.OrigCookies = [
            HTTPCookie.unmarshal(x) for x in msg.get("OrigCookies", []) or []
        ]
        o.Finished = msg.get("Finished", "") or ""
        o.Failure = msg.get("Failure", "") or ""
        o.FailedOperation = msg.get("FailedOperation", "") or ""
        o.NewCookies = [
            HTTPCookie.unmarshal(x) for x in msg.get("NewCookies", []) or []
        ]
        o.Location = MeasurexSimpleURL.unmarshal(msg.get("Location", {}) or {})
        o.HTTPTitle = msg.get("HTTPTitle", "") or ""
        o.NetworkEvent = []  # we ignore this field
        o.TCPConnect = FlatNetworkEvent.unmarshal(msg.get("TCPConnect", {}) or {})
        o.QUICTLSHandshake = FlatQUICTLSHandshake.unmarshal(
            msg.get("QUICTLSHandshake", {}) or {}
        )
        o.HTTPRoundTrip = FlatHTTPRoundTripEvent.unmarshal(
            msg.get("HTTPRoundTrip", {} or {})
        )
        return o

    def ip_address(self) -> str:
        """Returns the IP address we're using."""
        addr, _ = _split_address_port(self.Address)
        return addr

    def url_domain(self) -> str:
        """Returns the domain inside the URL."""
        if self.URL is None:
            return ""
        return self.URL.domain()

    def is_http_measurement(self) -> bool:
        """Returns whether this is an HTTP measurement."""
        if self.URL is None:
            return False
        return self.URL.Scheme == "http" and self.Network == "tcp"

    def is_https_measurement(self) -> bool:
        """Returns whether this is an HTTPS measurement."""
        if self.URL is None:
            return False
        return self.URL.Scheme == "https" and self.Network == "tcp"

    def is_http3_measurement(self) -> bool:
        """Returns whether this is an HTTP3 measurement."""
        # Note: QUIC is not implemented in this client
        if self.URL is None:
            return False
        return self.URL.Scheme == "https" and self.Network == "quic"

    def supports_alt_svc_http3(self) -> bool:
        """Return whether we know we support HTTP3 via Alt-Svc"""
        # Note: this is not implemented in Python
        return False

    def status_code(self) -> int:
        """Returns the response status code."""
        if self.HTTPRoundTrip is None:
            return 0
        return self.HTTPRoundTrip.StatusCode

    def redirect_summary(self) -> Tuple[str, Optional[MeasurexSimpleURL]]:
        """Computes the redirect summary for this URL measurement.

        See EndpointMeasurement.RedirectSummary in the Go implementation."""
        if not _is_http_redirect(self.status_code()):
            return "", None
        if self.Location is None:
            return "", None
        digest: List[str] = []
        # TODO(bassosimone): we should canonicalize the URL. If we don't do
        # that we may be following more redirects than needed.
        digest.append(self.Location.tostring())
        digest.extend(_sorted_serialized_cookies_names(self.NewCookies))
        return " ".join(digest), self.Location


class MeasurexMeasurer:
    """Performs measurex measurements.

    Corresponds to internal/measurex.Measurer."""

    def __init__(self, options: MeasurexOptions):
        self._idgen = MeasurexIDGenerator()
        self._options = options

    def next_id(self) -> int:
        """Returns the next measurement ID."""
        return self._idgen.next_id()

    def dns_lookups(
        self, plans: List[MeasurexDNSLookupPlan]
    ) -> Iterator[MeasurexDNSLookupMeasurement]:
        """Roughly corresponds to internal/measurex.Measurer.DNSLookups."""
        for plan in plans:
            if plan.lookup_type != "getaddrinfo":
                raise RuntimeError("we only support getaddrinfo")
            if plan.resolver.network != "system":
                raise RuntimeError("we only support the system resolver")
            yield self._dns_lookup_system(plan)

    def _dns_lookup_system(
        self, plan: MeasurexDNSLookupPlan
    ) -> MeasurexDNSLookupMeasurement:
        """Performs a lookup using the system resolver."""
        out = MeasurexDNSLookupMeasurement()
        out.ID = self.next_id()
        out.URLMeasurementID = plan.url_measurement_id
        saver = FlatSaver()
        result = saver.dns_lookup(plan.domain)
        trace = saver.move_out_trace()
        if len(trace.dns_lookup) != 1:
            raise RuntimeError("expected single trace.dns_lookup")
        out.Lookup = trace.dns_lookup[0]
        logging.info(f"[#{out.ID}] lookup {plan.domain}... {str(result)}")
        return out

    def measure_endpoints(
        self, plans: List[MeasurexEndpointPlan]
    ) -> Iterator[MeasurexEndpointMeasurement]:
        """Roughly corresponds to internal/measurex.Measurer.MeasureEndpoints."""
        for plan in plans:
            yield self._measure_endpoint(plan)

    def _measure_endpoint(
        self, plan: MeasurexEndpointPlan
    ) -> MeasurexEndpointMeasurement:
        """Measures a single HTTP/HTTPS endpoint."""
        if plan.url is None:
            raise RuntimeError("plan.url is None")
        if plan.network != "tcp":
            raise RuntimeError("we only support TCP")
        id = self.next_id()
        scheme = plan.url.Scheme
        if scheme not in ("http", "https"):
            raise RuntimeError("we only support HTTP and HTTPS")
        saver = FlatSaver()
        # "pconn" here should be read as "probably a conn"
        pconn = saver.tcp_connect(plan.address)
        logging.info(f"[#{id}] connect {plan.address}... {str(pconn)}")
        if pconn.is_err():
            return self._new_endpoint_measurement(
                id, plan, "tcp_connect", saver, pconn.failure_string()
            )
        conn = pconn.unwrap()
        if scheme == "https":
            sni = plan.domain
            alpns = ["http/1.1"]  # unfortunately we do not support HTTP/2
            ptconn = saver.tls_handshake(conn, sni, alpns)
            logging.info(f"[#{id}] tls_handshake {sni} {alpns}... {str(ptconn)}")
            if ptconn.is_err():
                conn.close()
                return self._new_endpoint_measurement(
                    id, plan, "tls_handshake", saver, pconn.failure_string()
                )
            anyconn = ptconn.unwrap()
        else:
            anyconn = conn
        url = plan.url.tostring()
        snapsize = self._options.snapsize_for_scheme_and_path(plan.url)
        hdrs = self._new_headers_with_cookies(plan.cookies)
        presp = saver.http_get(anyconn, url, hdrs, snapsize)
        logging.info(f"[#{id}] GET {url}... {str(presp)}")
        if presp.is_err():
            return self._new_endpoint_measurement(
                id, plan, "http_round_trip", saver, pconn.failure_string()
            )
        return self._new_endpoint_measurement(id, plan, "", saver, "")

    def _new_headers_with_cookies(self, cookies: List[HTTPCookie]) -> HTTPHeader:
        """Extends the existing HTTP headers set in the options
        to also include the given cookies."""
        headers = self._options.HTTPRequestHeaders.clone()
        outv = []
        for cookie in cookies:
            v = f"{cookie.Name}={cookie.Value}"
            sc = http.cookies.SimpleCookie()
            try:
                sc.load(v)
            except http.cookies.CookieError:
                continue  # This cookie does not seem valid
            outv.append(v)
        if outv:
            headers.headers.setdefault("Cookie", ["; ".join(outv)])
        return headers

    def _new_endpoint_measurement(
        self,
        id: int,
        plan: MeasurexEndpointPlan,
        failed_operation: str,
        saver: FlatSaver,
        failure: str,
    ) -> MeasurexEndpointMeasurement:
        """Constructs a new endpoint measurement."""
        out = MeasurexEndpointMeasurement()
        out.ID = id
        out.URLMeasurementID = plan.url_measurement_id
        out.URL = plan.url
        out.Network = plan.network
        out.Address = plan.address
        out.Options = plan.options
        out.OrigCookies = plan.cookies
        out.Finished = _time_now()
        out.Failure = failure
        out.FailedOperation = failed_operation
        out.NewCookies = []  # set later if possible
        out.Location = None  # ditto
        out.HTTPTitle = ""  # ditto
        out.NetworkEvent = []  # we'll not implement it
        trace = saver.move_out_trace()
        if len(trace.tcp_connect) != 1:
            raise RuntimeError("expected exactly one TCP connect entry")
        out.TCPConnect = trace.tcp_connect[0]
        if len(trace.quic_tls_handshake) > 0:
            if len(trace.quic_tls_handshake) != 1:
                raise RuntimeError("expected exactly one QUIC/TLS handshake")
            out.QUICTLSHandshake = trace.quic_tls_handshake[0]
        if len(trace.http_round_trip) > 0:
            if len(trace.http_round_trip) != 1:
                raise RuntimeError("expected exactly one HTTP round trip")
            out.HTTPRoundTrip = trace.http_round_trip[0]
            out.NewCookies = self._extract_cookies(out.HTTPRoundTrip)
            out.Location = self._extract_location(out.HTTPRoundTrip)
            out.HTTPTitle = self._extract_title(out.HTTPRoundTrip)
        return out

    @staticmethod
    def _extract_location(http: FlatHTTPRoundTripEvent) -> Optional[MeasurexSimpleURL]:
        """Attempts to extract the location from the response."""
        for key, values in http.ResponseHeaders.headers.items():
            if key != "Location":
                continue
            if len(values) != 1:
                break  # Should not happen (maybe we should warn here?)
            try:
                return MeasurexSimpleURL.parse(values[0])
            except ValueError:
                break

    # TODO(bassosimone): is this regexp good/sufficient? It has been take
    # from ooni/probe-legacy so probably it's good...
    TITLE_REGEXP = re.compile("<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    @classmethod
    def _extract_title(cls, http: FlatHTTPRoundTripEvent) -> str:
        """Attempts to extract the title from the webpage response."""
        try:
            b64 = base64.b64decode(http.ResponseBody, validate=True)
            sb = b64.decode("utf-8")
            m = cls.TITLE_REGEXP.search(sb, re.IGNORECASE | re.DOTALL)
            if m:
                return m.group(1)
        except binascii.Error:
            pass
        return ""

    class _CookieParser:
        """Wrapper to extract values from cookies."""

        def __init__(self, cookie: http.cookies.SimpleCookie):
            self._c = cookie

        def cookie(self) -> Optional[HTTPCookie]:
            """Returns a cookie from this cookie wrapper"""
            if len(self._c) != 1:
                raise RuntimeError("_CookieWrapper used incorrectly")
            for morsel in self._c.values():
                c = HTTPCookie()
                c.Name = morsel.key
                c.Value = morsel.value
                for key, value in morsel.items():
                    if key == "path":
                        c.Path = self._str(value)
                    elif key == "domain":
                        c.Domain = self._str(value)
                    elif key == "expires":
                        c.Expires = self._str(value)
                    elif key == "max-age":
                        c.MaxAge = self._str(value)
                    elif key == "secure":
                        c.Secure = self._str(value)
                    elif key == "httponly":
                        pass  # currently broken (see above)
                    elif key == "samesite":
                        pass  # currently broken (see above)
                return c

        @staticmethod
        def _str(value: Any) -> str:
            if isinstance(value, str):
                return value
            return ""

    @classmethod
    def _extract_cookies(cls, rtev: FlatHTTPRoundTripEvent) -> List[HTTPCookie]:
        """Attempts to extract cookies from the respoonse."""
        out: List[HTTPCookie] = []
        for key, values in rtev.ResponseHeaders.headers.items():
            if key != "Set-Cookie":
                continue
            for value in values:
                try:
                    sc = http.cookies.SimpleCookie(value)
                except http.cookies.CookieError:
                    continue
                c = cls._CookieParser(sc).cookie()
                if c is not None:
                    out.append(c)
        return out

    def new_url_measurement(self, url: str) -> MeasurexURLMeasurement:
        """Creates a new URLMeasurement for the given URL."""
        parsed = MeasurexSimpleURL.parse(url)
        out = MeasurexURLMeasurement()
        out.ID = self.next_id()
        out.Options = self._options
        out.URL = parsed
        return out

    def redirects(
        self, epnts: List[MeasurexEndpointMeasurement], opts: MeasurexOptions
    ) -> List[MeasurexURLMeasurement]:
        """Computes the list of redirects from the measured endpoints."""
        uniq: Dict[str, MeasurexURLMeasurement] = {}
        for epnt in epnts:
            summary, location = epnt.redirect_summary()
            if not summary or not location:
                continue
            if summary not in uniq:
                headers = self._new_headers_for_redirect(epnt.URL)
                newoptions = MeasurexOptions()
                newoptions.DoNotInitiallyForceHTTPAndHTTPS = True
                newoptions.HTTPRequestHeaders = headers
                next = MeasurexURLMeasurement()
                next.ID = self.next_id()
                next.EndpointIDs = [epnt.ID]
                next.URL = location
                next.Cookies = epnt.NewCookies
                next.Options = opts.clone_and_merge(newoptions)
                uniq[summary] = next
                continue
            next = uniq[summary]
            next.EndpointIDs.append(epnt.ID)
        out: List[MeasurexURLMeasurement] = []
        for value in uniq.values():
            out.append(value)
        return out

    @staticmethod
    def _new_headers_for_redirect(orig_url: Optional[MeasurexSimpleURL]) -> HTTPHeader:
        """Generates new headers for a redirection"""
        # Implementation note: because the TH filters the headers it
        # accepts when importing client options, we need to avoid sending
        # fancy headers. So, let's just re-create the standard headers
        # for measuring plus the referer. (Note: today the code was failing
        # to match the TH and the probe headers because the probe did also
        # include `Host`, which TH filters out, and obviously `Host` was
        # added by the probe here before we removed the code to derive
        # follow-up requests headers from previous ones.)
        out = HTTPHeader.default()
        if orig_url is not None:
            out.append("Referer", orig_url.tostring())
        return out

    def new_url_redirect_deque(self) -> MeasurexURLRedirectDeque:
        """Creates a new URL redirect deque."""
        return MeasurexURLRedirectDeque(self._options)


def new_url_address_list(
    ID: int,
    domain: str,
    dns: List[MeasurexDNSLookupMeasurement],
    endpoint: List[MeasurexEndpointMeasurement],
) -> List[MeasurexURLAddress]:
    """Generates a new URL address list from the given set of parameters.

    Corresponds to NewURLAddressList in internal/measurex/url.go."""
    # Note: the Go implementation tries not to mess up the order with which we
    # receive addresses so here we use an ordered dict.
    uniq: OrderedDict[str, int] = OrderedDict()

    # 1. start searching into the DNS results
    for d in dns:
        if domain != d.domain():
            continue
        flags = 0
        if d.supports_http3():
            flags |= MeasurexURLAddress.SUPPORTS_HTTP3
        if d.resolver_network() == "system":
            flags |= MeasurexURLAddress.SYSTEM_RESOLVER
        for addr in d.addresses():
            if _is_ip_addr(addr):
                uniq.setdefault(addr, 0)
                uniq[addr] |= flags

    # 2. continue searching into HTTP responses.
    for e in endpoint:
        if domain != e.url_domain():
            continue
        ipaddr = e.ip_address()
        if not ipaddr:
            continue
        if not _is_ip_addr(ipaddr):
            continue
        flags = 0
        if e.is_http_measurement():
            flags |= MeasurexURLAddress.ALREADY_TESTED_HTTP
        if e.is_https_measurement():
            flags |= MeasurexURLAddress.ALREADY_TESTED_HTTPS
        if e.is_http3_measurement():
            flags |= MeasurexURLAddress.ALREADY_TESTED_HTTP3
        if e.supports_alt_svc_http3():
            flags |= MeasurexURLAddress.SUPPORTS_HTTP3
        uniq.setdefault(ipaddr, 0)
        uniq[ipaddr] |= flags

    # 3. finally build the result
    out: List[MeasurexURLAddress] = []
    for key, value in uniq.items():
        ua = MeasurexURLAddress()
        ua.url_measurement_id = ID
        ua.address = key
        ua.domain = domain
        ua.flags = value
        out.append(ua)

    #
    # 4. zip together resolvers: not implemented in Python.
    #
    # The Go implementation here zips together addresses so that we have
    # an address from the system resolver followed by one from another
    # resolver followed by one from the system resolver and so on.
    #
    # The idea of this algorithm is that of ensuring we test at least
    # an IP address from the system resolver and an address from
    # another resolts. Because we only implement the system resolver
    # here, there's no point in writing this algorithm.
    #

    return out


class MeasurexURLMeasurement:
    """State for measuring a given URL.

    Corresponds to internal/measurex.URLMeasurement."""

    def __init__(self):
        self.ID: int = 0
        self.EndpointIDs: List[int] = []
        self.Options = MeasurexOptions()
        self.URL = MeasurexSimpleURL()
        self.Cookies: List[HTTPCookie] = []
        self.DNS: List[MeasurexDNSLookupMeasurement] = []
        self.Endpoint: List[MeasurexEndpointMeasurement] = []

    def __repr__(self):
        return f"<MeasurexURLMeasurement #{self.ID} for {self.URL.tostring()}>"

    def domain(self) -> str:
        """Returns the domain associated with this URLMeasurement."""
        return self.URL.domain()

    def new_dns_lookup_plans(
        self, ri: List[MeasurexDNSResolverInfo]
    ) -> List[MeasurexDNSLookupPlan]:
        """Creates a new DNS lookup plan for this URLMeasurement.

        Roughly corresponds to internal/measurex.URLMeasurement.NewDNSLookupPlan."""
        out: List[MeasurexDNSLookupPlan] = []
        for r in ri:
            plan = MeasurexDNSLookupPlan()
            plan.url_measurement_id = self.ID
            plan.domain = self.URL.domain()
            plan.lookup_type = "getaddrinfo"
            plan.options = self.Options
            plan.resolver = r
            out.append(plan)
        return out

    def new_endpoint_plan(self, flags: int) -> List[MeasurexEndpointPlan]:
        """Generates a new enpoint plan from this URLMeasurement."""
        addrs = self.url_address_list()
        return self.new_endpoint_plan_with_address_list(addrs, flags)

    def url_address_list(self) -> List[MeasurexURLAddress]:
        """Generates a new URL address list from the results of
        previous DNS lookups and endpoint measurements."""
        return new_url_address_list(self.ID, self.domain(), self.DNS, self.Endpoint)

    def is_http(self) -> bool:
        """Returns whether we should consider this URL an HTTP URL."""
        if self.URL is None:
            return False
        if not self.Options.DoNotInitiallyForceHTTPAndHTTPS:
            # When we're forcing to measure both HTTP and HTTPS it
            # doesn't matter what's the URL scheme.
            return True
        return self.URL.Scheme == "http"

    def is_https(self) -> bool:
        """Returns whether we should consider this URL an HTTPS URL."""
        if self.URL is None:
            return False
        if not self.Options.DoNotInitiallyForceHTTPAndHTTPS:
            # When we're forcing to measure both HTTP and HTTPS it
            # doesn't matter what's the URL scheme.
            return True
        return self.URL.Scheme == "https"

    # Same flags as the Go implementation
    ENDPOINT_PLANNING_EXCLUDE_BOGONS = 1 << 0
    ENDPOINT_PLANNING_ONLY_HTTP3 = 1 << 1
    ENDPOINT_PLANNING_INCLUDE_ALL = 1 << 2
    ENDPOINT_PLANNING_MEASURE_AGAIN = 1 << 3

    def new_endpoint_plan_with_address_list(
        self, addrs: List[MeasurexURLAddress], flags: int
    ) -> List[MeasurexEndpointPlan]:
        """Creates a plan for measuring endpoints given an URL address list."""
        out: List[MeasurexEndpointPlan] = []
        family_counter: Dict[str, int] = {}
        for addr in addrs:
            if (flags & self.ENDPOINT_PLANNING_EXCLUDE_BOGONS) != 0:
                raise RuntimeError("excluding bogons is not implemented")

            if not _is_ip_addr(addr.address):
                continue
            if _is_loopback(addr.address):
                logging.warning(
                    f"[mx] excluding loopback addresses such as {addr.address} by default"
                )
                continue
            family = "AAAA" if _is_ipv6(addr.address) else "A"
            if (flags & self.ENDPOINT_PLANNING_INCLUDE_ALL) == 0:
                if family_counter.get(family, 0) >= self.Options.MaxAddressesPerFamily:
                    logging.warning(
                        f"too many {family} addresses already, skipping {addr.address}"
                    )
                    continue

            counted = False
            again = (flags & self.ENDPOINT_PLANNING_MEASURE_AGAIN) != 0

            if (flags & self.ENDPOINT_PLANNING_ONLY_HTTP3) == 0:
                if self.is_http() and (not addr.already_tested_http() or again):
                    out.append(self._new_endpoint_plan("tcp", addr.address, "http"))

                if self.is_https() and (not addr.already_tested_https() or again):
                    out.append(self._new_endpoint_plan("tcp", addr.address, "https"))

                # Even if it has already been measured, this address still counts
                # against the limit enforced by MaxAddressesPerFamily.
                counted = True

            if self.is_https() and addr.supports_http3():
                if not addr.already_tested_http3() or again:
                    out.append(self._new_endpoint_plan("quic", addr.address, "https"))

                # Even if it has already been measured, this address still counts
                # against the limit enforced by MaxAddressesPerFamily.
                counted = True

            if counted:
                family_counter.setdefault(family, 0)
                family_counter[family] += 1

        return out

    def _new_endpoint_plan(
        self, network: str, address: str, scheme: str
    ) -> MeasurexEndpointPlan:
        """Internal function to create a new endpoint plan."""
        url = self.URL.clone_with_scheme(scheme)
        epnt = self._make_url_endpoint(url, address)
        out = MeasurexEndpointPlan()
        out.url_measurement_id = self.ID
        out.domain = self.domain()
        out.network = network
        out.address = epnt
        out.url = url
        out.options = self.Options
        out.cookies = self.Cookies
        return out

    @staticmethod
    def _make_url_endpoint(url: MeasurexSimpleURL, address: str) -> str:
        """Creates a suitable endpoint for the URL."""
        return _join_address_port(address, url.port())


class MeasurexURLAddress:
    """An IP address associated to an URL.

    Roughly corresponds to internal/measurex.URLAddress"""

    # Same flags used in the Go implementation
    SUPPORTS_HTTP3 = 1 << 0
    ALREADY_TESTED_HTTP = 1 << 1
    ALREADY_TESTED_HTTPS = 1 << 2
    ALREADY_TESTED_HTTP3 = 1 << 3
    SYSTEM_RESOLVER = 1 << 4

    def __init__(self):
        self.url_measurement_id = 0
        self.address = ""
        self.domain = ""
        self.flags = 0

    def supports_http3(self) -> bool:
        """Returns whether this address supports HTTP3."""
        return (self.flags & self.SUPPORTS_HTTP3) != 0

    def already_tested_http(self) -> bool:
        """Returns whether we've already tested this address using HTTP."""
        return (self.flags & self.ALREADY_TESTED_HTTP) != 0

    def already_tested_https(self) -> bool:
        """Returns whether we've already tested this address using HTTPS."""
        return (self.flags & self.ALREADY_TESTED_HTTPS) != 0

    def already_tested_http3(self) -> bool:
        """Returns whether we've already tested this address using HTTP3."""
        return (self.flags & self.ALREADY_TESTED_HTTP3) != 0


class MeasurexURLRedirectDeque:
    """The type we use to manage redirections.

    Roughly corresponding to internal/measurex.URLRedirectDeque."""

    #
    # TODO(bassosimone): both this implementation and the Go implementation
    # do not take into account cookies when deciding whether we've already
    # measured a given URL, which is quite wrong.
    #

    def __init__(self, options: MeasurexOptions):
        self._depth = 0
        self._mem: Dict[str, bool] = {}
        self._options = options
        self._q: Deque[MeasurexURLMeasurement] = deque()

    def depth(self) -> int:
        """Returns the current depth"""
        return self._depth

    def __str__(self) -> str:
        return str([str(x) for x in self._q])

    def append(self, ums: List[MeasurexURLMeasurement]):
        """Appends one or more URL measurements to the deque."""
        for um in ums:
            self._q.append(um)

    def remember_visited_urls(self, epnts: List[MeasurexEndpointMeasurement]):
        """Remebers which URLs we've already visited."""
        for epnt in epnts:
            if epnt.URL is not None:
                self._mem[self._canonical_url(epnt.URL)] = True

    def max_depth(self) -> int:
        """Returns the maximum allowed crawler depth."""
        return self._options.MaxCrawlerDepth

    def popleft(self) -> Optional[MeasurexURLMeasurement]:
        """Returns the next URL to measure or None if we either exceeded
        the maximum crawler depth or the deque is now empty."""
        if self._depth >= self._options.MaxCrawlerDepth:
            logging.info("exceeded the maximum crawler depth")
            return None
        while len(self._q) > 0:
            um = self._q.popleft()
            if um.URL is None:
                logging.warning("popped None um.url from queue")
                continue
            if self._mem.get(self._canonical_url(um.URL)):
                logging.info(f"we already measured {self._canonical_url(um.URL)}")
                continue
            self._depth += 1
            return um
        logging.info(f"the redirect queue is empty")

    @staticmethod
    def _canonical_url(url: MeasurexSimpleURL) -> str:
        # TODO(bassosimone): the more aggressively we canonicalize URLs
        # the less we remeasure actually equivalent URLs.
        url = url.clone()
        if url.Path == "":
            url.Path = "/"
        return url.tostring()


class MeasurexCrawler:
    """A crawler that follows redirects. This class is basically a simplified
    version of the algorithm implemented by websteps.

    (Technically this class is not needed to implement websteps, but when you
    arrive at this point you definitely want something to test everything
    together before implementing websteps proper.)

    Roughly corresponds to internal/measurex.Crawler."""

    def __init__(self, options: MeasurexOptions):
        self._measurer = MeasurexMeasurer(options)
        self._options = options
        self._resolvers = [MeasurexDNSResolverInfo.system()]

    def crawl(self, url: str) -> Iterator[MeasurexURLMeasurement]:
        """Measures the given URL and a few redirections."""
        mx = self._measurer
        initial = mx.new_url_measurement(url)
        q = mx.new_url_redirect_deque()
        q.append([initial])
        while True:
            cur = q.popleft()
            if not cur:
                break
            logging.info(f"depth={q.depth()}; crawling {cur}")
            self._step(mx, cur)
            q.remember_visited_urls(cur.Endpoint)
            redirects = mx.redirects(cur.Endpoint, cur.Options)
            yield cur
            q.append(redirects)
            logging.info(f"work queue: {q}")

    def _step(self, mx: MeasurexMeasurer, cur: MeasurexURLMeasurement):
        """Single crawling step."""
        logging.info("resolving the domain using all resolvers")
        dnsplans = cur.new_dns_lookup_plans(self._resolvers)
        for m in mx.dns_lookups(dnsplans):
            cur.DNS.append(m)
        logging.info("visiting endpoints deriving from DNS")
        epntplans = cur.new_endpoint_plan(0)
        for m in mx.measure_endpoints(epntplans):
            cur.Endpoint.append(m)
        # Implementation note: because we don't implement QUIC
        # and HTTP/3, we cannot check for HTTP/3 endpoints discovered
        # by inspecting Alt-Svc headers here.


def url_address_list_diff(
    A: List[MeasurexURLAddress], B: List[MeasurexURLAddress]
) -> List[MeasurexURLAddress]:
    """Returns the addresses that belong to A but do not belong to B."""
    # The implementation in Go is a bit more complex than this but in retrospect
    # we only probably need something as simple as this also in Go.
    ina, inb = 1 << 0, 1 << 1
    m: Dict[MeasurexURLAddress, int] = {}
    for e in A:
        m.setdefault(e, 0)
        m[e] |= ina
    for e in B:
        m.setdefault(e, 0)
        m[e] |= inb
    o: List[MeasurexURLAddress] = []
    for k, v in m.items():
        if (v & (ina | inb)) == ina:
            o.append(k)
    return o


#
# Websteps
#
# Implementation of the websteps OONI experiment.
#


class WebstepsTestKeys:
    """Contains the test keys produced by the websteps experiment.

    Roughly corresponds to internal/engine/experiment/websteps.TestKeys."""

    def __init__(self):
        self.URL: str = ""
        self.Steps: List[WebstepsSingleStepMeasurement] = []
        self.Flags = 0


class WebstepsTHResponse:
    """Contains the response from the TH.

    Roughly corresponds to internal/engine/experiment/websteps.THResponse."""

    def __init__(self):
        self.DNS: List[MeasurexDNSLookupMeasurement] = []
        self.Endpoint: List[MeasurexEndpointMeasurement] = []

    @staticmethod
    def unmarshal(msg: Dict) -> WebstepsTHResponse:
        out = WebstepsTHResponse()
        for dns in msg["DNS"]:
            out.DNS.append(MeasurexDNSLookupMeasurement.unmarshal(dns))
        for epnt in msg["Endpoint"]:
            out.Endpoint.append(MeasurexEndpointMeasurement.unmarshal(epnt))
        return out

    def url_address_list(self, ID: int, domain: str) -> List[MeasurexURLAddress]:
        """Returns the URLAddress list discovered by the TH."""
        return new_url_address_list(ID, domain, self.DNS, self.Endpoint)


class WebstepsAnalysis:
    """Contains the results of the analysis.

    Roughly corresponds to internal/engine/experiment/websteps.Analysis."""

    #
    # Implementation note: because this websteps implementation does
    # not implement any analysis, we just use a stub structure that
    # the pipeline will understand without incurring into the burden
    # of defining all the types we'd need here.
    #

    def __init__(self):
        self.DNS = []
        self.Endpoint = []
        self.TH = []


class WebstepsSingleStepMeasurement:
    """Result of a single websteps step.

    Roughly corresponds to internal/engine/experiment/websteps.SingleStepMeasurement."""

    def __init__(self):
        self.ProbeInitial: Optional[MeasurexURLMeasurement] = None
        self.TH: Optional[WebstepsTHResponse] = None
        self.DNSPing = None
        self.ProbeAdditional: List[MeasurexEndpointMeasurement] = []
        self.Analysis: Optional[WebstepsAnalysis] = None
        self.Flags = 0

    def _remember_visited_urls(self, q: MeasurexURLRedirectDeque):
        """Remembers all the URLs we've already visited."""
        if self.ProbeInitial is not None:
            q.remember_visited_urls(self.ProbeInitial.Endpoint)
        q.remember_visited_urls(self.ProbeAdditional)

    def _redirects(self, mx: MeasurexMeasurer) -> List[MeasurexURLMeasurement]:
        """Returns all the discovered redirects."""
        out: List[MeasurexURLMeasurement] = []
        if self.ProbeInitial is None:
            return []
        r1 = mx.redirects(self.ProbeInitial.Endpoint, self.ProbeInitial.Options)
        out.extend(r1)
        if self.TH is not None:
            r2 = mx.redirects(self.TH.Endpoint, self.ProbeInitial.Options)
            out.extend(r2)
        r3 = mx.redirects(self.ProbeAdditional, self.ProbeInitial.Options)
        out.extend(r3)
        return out

    @staticmethod
    def create(cur: MeasurexURLMeasurement) -> WebstepsSingleStepMeasurement:
        """Creates a single step measurement from the given URL measurement."""
        out = WebstepsSingleStepMeasurement()
        out.ProbeInitial = cur
        out.TH = WebstepsTHResponse()
        out.ProbeAdditional = []
        out.Analysis = WebstepsAnalysis()
        return out

    def probe_initial_url_address_list(self) -> List[MeasurexURLAddress]:
        """Returns the list of URL addresses discovered by the probe in the
        initial measurement based on the DNS."""
        if self.ProbeInitial is None:
            return []
        return self.ProbeInitial.url_address_list()

    def probe_initial_domain(self) -> str:
        """Returns the domain used in the initial probe measurement."""
        if self.ProbeInitial is None:
            return ""
        return self.ProbeInitial.domain()

    def probe_initial_id(self) -> int:
        """Returns the ID used by the probe initial measurement."""
        if self.ProbeInitial is None:
            return 0
        return self.ProbeInitial.ID

    def test_helper_url_address_list(self) -> List[MeasurexURLAddress]:
        """Returns the list of URL adddresses discovered by the TH."""
        if self.TH is None:
            return []
        return self.TH.url_address_list(
            self.probe_initial_id(), self.probe_initial_domain()
        )


class WebstepsClient:
    """Client for the websteps experiment.

    Roughly corresponds to internal/engine/experiment/websteps.Client."""

    def __init__(self, options: MeasurexOptions):
        self._options = options
        self._resolvers = [MeasurexDNSResolverInfo.system()]
        self._th_url = "https://0.th.ooni.org/websteps/v1/http"

    # Same flags used by the Go implementation.
    LOOP_FLAG_GREEDY = 1 << 0

    def steps(self, url: str, flags: int) -> WebstepsTestKeys:
        """Performs steps to measure the given URL.

        Roughly corresponds to internal/engine/experiment/websteps.Client.steps."""
        mx = MeasurexMeasurer(self._options)
        initial = mx.new_url_measurement(url)
        logging.info(
            f"you asked me to measure '{url}' and up to {self._options.MaxCrawlerDepth} redirects... let's go!"
        )
        q = mx.new_url_redirect_deque()
        q.append([initial])
        tk = WebstepsTestKeys()
        tk.URL = url
        while True:
            cur = q.popleft()
            if not cur:
                break
            logging.info(f"now measuring {cur}")
            ssm = self._step(mx, cur)
            ssm._remember_visited_urls(q)
            redirects = ssm._redirects(mx)
            tk.Steps.append(ssm)
            q.append(redirects)
            if (flags & self.LOOP_FLAG_GREEDY) != 0:
                logging.warning("greedy mode: not implemented yet")
            logging.info(f"work queue: {q}")
        return tk

    def _step(
        self, mx: MeasurexMeasurer, cur: MeasurexURLMeasurement
    ) -> WebstepsSingleStepMeasurement:
        """Performs a single measurement step.

        Roughly corresponds to internal/engine/experiment/websteps.Client.step."""
        self._dns_lookup(mx, cur)
        ssm = WebstepsSingleStepMeasurement.create(cur)
        epplan = cur.new_endpoint_plan(0)
        self._measure_discovered_endpoints(mx, cur, epplan)
        ssm.TH = self._th(mx, cur, epplan)
        self._measure_additional_endpoints(mx, ssm)
        return ssm

    def _dns_lookup(self, mx: MeasurexMeasurer, cur: MeasurexURLMeasurement):
        """Performs the DNS lookup part of the step"""
        # Implementation note: the Go implementation uses a DNS cache to
        # avoid performing the same DNS lookup again in a subsequent step
        # while we don't implement this functionality.
        logging.info(f"resolving {cur.domain()} to IP addresses")
        dnsplans = cur.new_dns_lookup_plans(self._resolvers)
        for m in mx.dns_lookups(dnsplans):
            cur.DNS.append(m)

    def _measure_discovered_endpoints(
        self,
        mx: MeasurexMeasurer,
        cur: MeasurexURLMeasurement,
        epplan: List[MeasurexEndpointPlan],
    ):
        """Measures all the endpoints we discovered with the DNS."""
        logging.info(
            f"now testing {len(epplan)} HTTP/HTTPS/HTTP3 endpoints deriving from the discovered IP addresses"
        )
        for m in mx.measure_endpoints(epplan):
            cur.Endpoint.append(m)

    def _measure_additional_endpoints(
        self,
        mx: MeasurexMeasurer,
        ssm: WebstepsSingleStepMeasurement,
    ):
        """Measures additional endpoints discovered by the TH."""
        if ssm.ProbeInitial is None:
            return
        addrslist = self._expand_probe_knowledge(ssm)
        # Here we need to specify "measure again" because the addresses appear to be
        # already tested though it's the TH that has tested them, not us.
        plan = ssm.ProbeInitial.new_endpoint_plan_with_address_list(
            addrslist,
            MeasurexURLMeasurement.ENDPOINT_PLANNING_MEASURE_AGAIN,
        )
        logging.info(
            f"now testing additional HTTP/HTTPS/HTTP3 endpoints deriving from the TH"
        )
        for m in mx.measure_endpoints(plan):
            ssm.ProbeAdditional.append(m)

    def _th(
        self,
        mx: MeasurexMeasurer,
        cur: MeasurexURLMeasurement,
        epplan: List[MeasurexEndpointPlan],
    ) -> WebstepsTHResponse:
        """Invokes the TH and returns its response."""
        c = WebstepsTHClient(mx, cur, epplan, self._th_url)
        return c.round_trip()

    def _expand_probe_knowledge(
        self,
        ssm: WebstepsSingleStepMeasurement,
    ) -> List[MeasurexURLAddress]:
        """Expands the probe's knowledge by including the new IP
        addresses discovered by the test helper."""
        # 1. gather the list for the probe and the TH
        pal = ssm.probe_initial_url_address_list()
        thal = ssm.test_helper_url_address_list()
        # 2. only keep new addresses.
        return url_address_list_diff(thal, pal)


class WebstepsTHClient:
    """Client for speaking to the TH."""

    def __init__(
        self,
        mx: MeasurexMeasurer,
        cur: MeasurexURLMeasurement,
        epplan: List[MeasurexEndpointPlan],
        url: str,
    ):
        self._measurer = mx
        self._cur = cur
        self._epplan = epplan
        self._th_url = url

    def round_trip(self) -> WebstepsTHResponse:
        """Sends the request to the test helper and returns its response."""
        try:
            return self._round_trip()
        except Exception as exc:
            logging.warning(f"round trip with TH failed: {exc}")
            return WebstepsTHResponse()

    def _round_trip(self) -> WebstepsTHResponse:
        """Internal worker for round_trip."""
        logging.info(f"querying the TH at {self._th_url}")
        req = WebstepsTHRequest.create(self._cur, self._epplan)
        ctx = ssl.create_default_context()
        conn = urlopen(self._th_url, _json_marshal(req).encode("utf-8"), context=ctx)
        if conn.status != 200:
            raise RuntimeError("TH returned: {conn.status}")
        data = conn.read()
        msg = json.loads(data)
        return self._import_th_response(WebstepsTHResponse.unmarshal(msg))

    def _import_th_response(self, thr: WebstepsTHResponse) -> WebstepsTHResponse:
        """Modifies the response from the TH to add correct URL references and IDs."""
        now = _time_now()
        for dlm in thr.DNS:
            dlm.ID = self._measurer.next_id()
            dlm.URLMeasurementID = self._cur.ID
            if dlm.Lookup is not None:
                self._import_dns_lookup(dlm.Lookup, now)
        for emr in thr.Endpoint:
            emr.ID = self._measurer.next_id()
            emr.URLMeasurementID = self._cur.ID
            emr.Finished = now
            if emr.HTTPRoundTrip is not None:
                self._import_http_round_trip(emr.HTTPRoundTrip, now)
        return thr

    def _import_dns_lookup(self, dlm: FlatDNSLookupEvent, now: str):
        """Modifies the times of the DNS lookup measurement."""
        dlm.Finished = now
        dlm.Started = now

    def _import_http_round_trip(self, hrt: FlatHTTPRoundTripEvent, now: str):
        """Modifies the times of the HTTP round trip event."""
        hrt.Finished = now
        hrt.Started = now


class WebstepsTHRequest:
    """Request for the test helper."""

    #
    # TODO(bassosimone): what is the point of serializing cookies when
    # sending them to the TH when we can send them directly?!
    #
    # Likewise, what is the point of serializing the URL when the TH
    # already understands the concept of a SimpleURL?!
    #
    # Also, while sending the outer URL when maybe we can just
    # send there the domain, since the real URL is anyway inside
    # of the endpoints plan?!
    #
    # Bottom line: we can simplify the protocol to speak with
    # the TH a little bit and we should do that!
    #

    def __init__(self):
        self.URL = ""
        self.Options = MeasurexOptions()
        self.Cookies = []  # TODO(bassosimone): implement
        self.Plan: List[WebstepsTHRequestEndpointPlan] = []

    @staticmethod
    def create(
        cur: MeasurexURLMeasurement, plan: List[MeasurexEndpointPlan]
    ) -> WebstepsTHRequest:
        out = WebstepsTHRequest()
        out.URL = cur.URL.tostring()
        out.Plan = WebstepsTHRequestEndpointPlan.create(plan)
        return out


class WebstepsTHRequestEndpointPlan:
    """Endpoint plan sent along with TH request."""

    def __init__(self):
        self.Network = ""
        self.Address = ""
        self.URL = ""

    @staticmethod
    def create(
        epplan: List[MeasurexEndpointPlan],
    ) -> List[WebstepsTHRequestEndpointPlan]:
        out: List[WebstepsTHRequestEndpointPlan] = []
        for plan in epplan:
            if plan.url is None:
                continue
            ep = WebstepsTHRequestEndpointPlan()
            ep.Network = plan.network
            ep.Address = plan.address
            ep.URL = plan.url.tostring()
            out.append(ep)
        return out


if __name__ == "__main__":
    import sys

    def main():
        options = MeasurexOptions()
        client = WebstepsClient(options)
        tk = client.steps(sys.argv[1], 0)
        print(_json_marshal(tk))

    main()
