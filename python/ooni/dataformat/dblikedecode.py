"""
Decodes DNS and HTTP round trips and DNS pings in DBLike format
producing low level information about what happened.
"""

import base64
from dnslib import DNSRecord
from urllib.parse import urlparse

from .dblike import (
    DBLikeEntry,
    DBLikeKind,
    DBLikeOrigin,
)

from .archival import (
    MeasurexArchivalEndpointMeasurement,
    MeasurexArchivalDNSLookupMeasurement,
    DNSPingArchivalSinglePingReply,
    DNSPingArchivalSinglePingResult,
)


def _http(origin: DBLikeOrigin, http: MeasurexArchivalEndpointMeasurement):
    """Attempts to decode an HTTP round trip."""
    raw = http.raw
    # Explanation: there was a bug where the name of the variable
    # was `requests` even though it was a single request. We're going
    # to keep the old name around because we have traces that use
    # the old name and it would be a pity to not decode them.
    #
    # This bug was fixed before 2022-03-22 though.
    req = raw.get("request")
    if req is None:
        req = raw.get("requests")
        if req is None:
            print("")
            print(f"BUG: did not find request or requests: {raw}")
            print("")
            return
    reqdata = req.get("request")
    if not reqdata:
        return
    print("")
    print(f"// origin: {origin}")
    print(f"// endpoint: {http.address}/{http.network}")
    print(f"// url: {http.url}")
    print("")
    method = reqdata["method"]
    url = reqdata["url"]
    parsed = urlparse(url)
    pathquery = parsed.path
    if parsed.query:
        pathquery += "?" + parsed.query
    print(f"> {method} {pathquery}")
    hdrs = reqdata.get("headers_list")
    if hdrs:
        for hdr in hdrs:
            print(f"> {hdr[0]}: {hdr[1]}")
    print(">")
    respdata = req.get("response")
    if respdata:
        status = respdata.get("code")
        if status is not None and status > 0:
            print(f"< {status}")
            hdrs = respdata.get("headers_list")
            if hdrs:
                for hdr in hdrs:
                    print(f"< {hdr[0]}: {hdr[1]}")
            print("<")
            print("")
            bodylength = respdata.get("body_length")
            print(f"// body_length: {bodylength}")
            bodytrunc = respdata.get("body_is_truncated")
            print(f"// body_is_truncated: {bodytrunc}")
            bodytlsh = respdata.get("body_tlsh")
            print(f"// body_tlsh: {bodytlsh}")
            body = respdata.get("body")
            print("")
            print(body)
    print("")
    failure = req.get("failure")
    if failure:
        print(f"ERROR: {failure}")
        print("")


def _dns(dns: MeasurexArchivalDNSLookupMeasurement):
    """Attempts to decode DNS round trips."""
    raw = dns.raw
    rtlist = raw.get("queries")
    if not rtlist:
        print("nothing to decode")
        return
    for idx, rt in enumerate(rtlist):
        print(f"decoding DNS round trip {idx}:")
        raw_query = rt.get("raw_query")
        if not raw_query:
            continue
        if raw_query.get("format", "") != "base64":
            continue
        print("")
        print(DNSRecord.parse(base64.b64decode(raw_query.get("data"))))
        print("")
        raw_reply = rt.get("raw_reply")
        if not raw_reply:
            continue
        if raw_reply.get("format", "") != "base64":
            continue
        print("")
        print(DNSRecord.parse(base64.b64decode(raw_reply.get("data"))))
        print("")


def entry(entry: DBLikeEntry):
    """Decodes the given entry."""
    if entry.kind() == DBLikeKind.ENDPOINT:
        _http(entry.origin(), entry.unwrap())
        return
    if entry.kind() == DBLikeKind.DNS:
        _dns(entry.unwrap())
        return
    if entry.kind() == DBLikeKind.DNS_SINGLE_PING_RESULT:
        result: DNSPingArchivalSinglePingResult = entry.unwrap()
        print(DNSRecord.parse(result.query))
        return
    if entry.kind() == DBLikeKind.DNS_SINGLE_PING_REPLY:
        reply: DNSPingArchivalSinglePingReply = entry.unwrap()
        print(DNSRecord.parse(reply.reply))
        return
    print(f"s: cannot decode: {entry}")
