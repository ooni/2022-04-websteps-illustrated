"""
Decodes DNS and HTTP round trips and DNS pings in DBLike format
producing low level information about what happened.
"""

import base64
import io
import logging
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


def _http(origin: DBLikeOrigin, http: MeasurexArchivalEndpointMeasurement) -> str:
    """Attempts to decode an HTTP round trip."""
    ob = io.StringIO()
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
            logging.warning(f"BUG: did not find request or requests: {raw}")
            return ""
    reqdata = req.get("request")
    if not reqdata:
        logging.warning(f"BUG: did not find request: {raw}")
        return ""
    print("", file=ob)
    print(f"// origin: {origin}", file=ob)
    print(f"// endpoint: {http.address}/{http.network}", file=ob)
    print(f"// url: {http.url}", file=ob)
    print("", file=ob)
    method = reqdata["method"]
    url = reqdata["url"]
    parsed = urlparse(url)
    pathquery = parsed.path
    if parsed.query:
        pathquery += "?" + parsed.query
    print(f"> {method} {pathquery}", file=ob)
    hdrs = reqdata.get("headers_list")
    if hdrs:
        for hdr in hdrs:
            print(f"> {hdr[0]}: {hdr[1]}", file=ob)
    print(">", file=ob)
    respdata = req.get("response")
    if respdata:
        status = respdata.get("code")
        if status is not None and status > 0:
            print(f"< {status}", file=ob)
            hdrs = respdata.get("headers_list")
            if hdrs:
                for hdr in hdrs:
                    print(f"< {hdr[0]}: {hdr[1]}", file=ob)
            print("<", file=ob)
            print("", file=ob)
            bodylength = respdata.get("body_length")
            print(f"// body_length: {bodylength}", file=ob)
            bodytrunc = respdata.get("body_is_truncated")
            print(f"// body_is_truncated: {bodytrunc}", file=ob)
            bodytlsh = respdata.get("body_tlsh")
            print(f"// body_tlsh: {bodytlsh}", file=ob)
            body = respdata.get("body")
            print("", file=ob)
            print(body, file=ob)
            print("", file=ob)
    print("", file=ob)
    failure = req.get("failure")
    if failure:
        print(f"ERROR: {failure}", file=ob)
        print("", file=ob)
    return ob.getvalue()


def _dns(dns: MeasurexArchivalDNSLookupMeasurement) -> str:
    """Attempts to decode DNS round trips."""
    ob = io.StringIO()
    raw = dns.raw
    rtlist = raw.get("queries")
    if not rtlist:
        logging.warning(f"nothing to decode in {raw}")
        return ""
    for idx, rt in enumerate(rtlist):
        print(f"decoding DNS round trip {idx}:", file=ob)
        raw_query = rt.get("raw_query")
        if not raw_query:
            continue
        if raw_query.get("format", "") != "base64":
            continue
        print("", file=ob)
        print(DNSRecord.parse(base64.b64decode(raw_query.get("data"))), file=ob)
        print("", file=ob)
        raw_reply = rt.get("raw_reply")
        if not raw_reply:
            continue
        if raw_reply.get("format", "") != "base64":
            continue
        print("", file=ob)
        print(DNSRecord.parse(base64.b64decode(raw_reply.get("data"))), file=ob)
        print("", file=ob)
    return ob.getvalue()


def entry(entry: DBLikeEntry) -> str:
    """Decodes the given entry."""
    if entry.kind() == DBLikeKind.ENDPOINT:
        return _http(entry.origin(), entry.unwrap())
    if entry.kind() == DBLikeKind.DNS:
        return _dns(entry.unwrap())
    if entry.kind() == DBLikeKind.DNS_SINGLE_PING_RESULT:
        result: DNSPingArchivalSinglePingResult = entry.unwrap()
        return str(DNSRecord.parse(result.query))
    if entry.kind() == DBLikeKind.DNS_SINGLE_PING_REPLY:
        reply: DNSPingArchivalSinglePingReply = entry.unwrap()
        return str(DNSRecord.parse(reply.reply))
    logging.warning(f"s: cannot decode: {entry}")
    return ""
