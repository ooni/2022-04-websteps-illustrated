"""
Decodes HTTP and DNS round trips.

This module is a support module for testcase.py.
"""

import base64
from dnslib import DNSRecord

from ..dataformat.flat import (
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


def _decode_and_print_dns_message(data: str):
    print("")
    if data:
        print(DNSRecord.parse(base64.b64decode(data)))
    else:
        print("warning: no query or reply data (most likely network failure)")


def decode_and_print_dns(probe_th: str, dns: MeasurexDNSLookupMeasurement):
    print(f"{probe_th}: [#{dns.id}] {dns.lookup.lookup_type} {dns.lookup.domain}")
    print(f"{probe_th}: [#{dns.id}] using resolver {dns.lookup.resolver_url()}...")
    for idx, round_trip in enumerate(dns.round_trip):
        print(f"showing round trip {idx}:")
        _decode_and_print_dns_message(round_trip.query)
        _decode_and_print_dns_message(round_trip.reply)
    print(f"{probe_th}: [#{dns.id}] result: {_failure_or_null(dns.lookup.failure)}")
    print("")


def decode_and_print_endpoint(probe_th: str, epnt: MeasurexEndpointMeasurement):
    print(f"{probe_th}: [#{epnt.id}] GET {epnt.url}")
    print(f"{probe_th}: [#{epnt.id}] using {epnt.address}/{epnt.network}...")
    if probe_th == "probe":  # we don't have this info for the TH
        if epnt.network == "tcp":
            print(f"tcp_connect... {_failure_or_okay(epnt.tcp_connect.failure)}")
        if epnt.url.scheme == "https" and not epnt.tcp_connect.failure:
            print(f"handshake... {_failure_or_okay(epnt.quic_tls_handshake.failure)}")
    if not epnt.failure:
        print(f"> GET {epnt.url}")
        for key, values in epnt.http_round_trip.request_headers.headers.items():
            for value in values:
                print(f"> {key}: {value}")
        print(">")
        if not epnt.http_round_trip.failure:
            print(f"< {epnt.http_round_trip.status_code}")
            for (
                key,
                values,
            ) in epnt.http_round_trip.response_headers.headers.items():
                for value in values:
                    print(f"< {key}: {value}")
            print("<")
            if epnt.response_body_length() > 0:
                print(f"# body_length: {epnt.response_body_length()}")
            if probe_th == "probe" and epnt.http_round_trip.response_body:
                body = base64.b64decode(epnt.http_round_trip.response_body)
                print(body.decode("utf-8"))
    print(f"{probe_th}: [#{epnt.id}] result: {_failure_or_null(epnt.failure)}")
    print("")
