"""
Decodes "flat" HTTP and DNS round trips.

This module is a support module for flat.py.
"""

import base64
import io
from typing import TextIO
from dnslib import DNSRecord

from .flat import (
    MeasurexDNSLookupMeasurement,
    MeasurexEndpointMeasurement,
)


def _failure_or_null(flat_failure: str) -> str:
    if flat_failure == "":
        return "null"
    return flat_failure


def _failure_or_okay(flat_failure: str) -> str:
    if flat_failure == "":
        return "ok"
    return flat_failure


def _dns_message(data: str, out: TextIO):
    print("", file=out)
    if data:
        print(DNSRecord.parse(base64.b64decode(data)), file=out)
    else:
        print("warning: no query or reply data (network failure?)", file=out)


def dns(probe_th: str, dns: MeasurexDNSLookupMeasurement) -> str:
    out = io.StringIO()
    print(
        f"{probe_th}: [#{dns.id}] {dns.lookup.lookup_type} {dns.lookup.domain}",
        file=out,
    )
    print(f"{probe_th}: [#{dns.id}] resolver {dns.lookup.resolver_url()}...", file=out)
    for idx, round_trip in enumerate(dns.round_trip):
        print(f"showing round trip {idx}:", file=out)
        _dns_message(round_trip.query, out)
        _dns_message(round_trip.reply, out)
    print(
        f"{probe_th}: [#{dns.id}] result: {_failure_or_null(dns.lookup.failure)}",
        file=out,
    )
    print("", file=out)
    return out.getvalue()


def endpoint(probe_th: str, epnt: MeasurexEndpointMeasurement) -> str:
    out = io.StringIO()
    print(f"{probe_th}: [#{epnt.id}] GET {epnt.url}", file=out)
    print(f"{probe_th}: [#{epnt.id}] using {epnt.address}/{epnt.network}...", file=out)
    if probe_th == "probe":  # we don't have this info for the TH
        if epnt.network == "tcp":
            print(
                f"tcp_connect... {_failure_or_okay(epnt.tcp_connect.failure)}", file=out
            )
        if epnt.url.scheme == "https" and not epnt.tcp_connect.failure:
            print(
                f"handshake... {_failure_or_okay(epnt.quic_tls_handshake.failure)}",
                file=out,
            )
    if not epnt.failure:
        print(f"> GET {epnt.url}", file=out)
        for key, values in epnt.http_round_trip.request_headers.headers.items():
            for value in values:
                print(f"> {key}: {value}", file=out)
        print(">", file=out)
        if not epnt.http_round_trip.failure:
            print(f"< {epnt.http_round_trip.status_code}", file=out)
            for (
                key,
                values,
            ) in epnt.http_round_trip.response_headers.headers.items():
                for value in values:
                    print(f"< {key}: {value}", file=out)
            print("<", file=out)
            if epnt.response_body_length() > 0:
                print(f"# body_length: {epnt.response_body_length()}", file=out)
            if probe_th == "probe" and epnt.http_round_trip.response_body:
                body = base64.b64decode(epnt.http_round_trip.response_body)
                print(body.decode("utf-8"), file=out)
    print(
        f"{probe_th}: [#{epnt.id}] result: {_failure_or_null(epnt.failure)}", file=out
    )
    print("", file=out)
    return out.getvalue()
