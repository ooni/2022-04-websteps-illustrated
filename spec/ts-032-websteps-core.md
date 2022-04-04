# Websteps: measuring HTTP/HTTPS/HTTP3 blocking

Websteps is a redesign of OONI's webconnectivity experiment. This
document only contains the core specification. Separate
documents describe other websteps related topics.

| | |
| -- | -- |
| Version | 2022.04.04 |
| Author | Simone Basso |
| Status | Draft |


## Table of contents

1. Overview
2. Measurement algorithm
3. Archival data format
4. Data analysis
5. Privacy considerations


## 1. Overview

Websteps performs DNS and endpoints measurements starting
from an _initial URL_ (e.g., `http://example.com`) that typically is
part of a list of URLs to measure.

Measuring an URL entails:

1. discovering IP addresses for the domain in the URL;

2. measuring each TCP or UDP endpoint constructed from those IP
addresses by establishing a TCP/TCP+TLS/QUIC session, sending an
HTTP/HTTPS/HTTP3 GET request, and reading the response;

3. discovering and following redirects until there are no more
redirects to follow, or we suspect there is a redirect loop.

Each redirect is an independent measurement step.

The most straightforward websteps implementation follows all redirects
and measures all the discovered endpoints. However, there are two reasons
to limit the number of redirects and the number of endpoints
measured per step:

1. typically, OONI runs with an input list of URLs and has a
limited time budget to perform these measurements; hence we need
to strike a balance between measuring a single URL in detail
and visiting all the URLs in the input list;

2. additionally, OONI visits a single URL in
the input list at a time. Therefore, we tend to increase parallelism
to measure more URLs within the given time budget. However, we have
experimentally seen that measuring all the endpoints of a given
URL concurrently could trigger rate limiting. (For example, we have
seen this happening for `linkedin.com` in China, where the
servers started replying with `420 Enhance your calm`.)

If we remove the constraints on the time budget and sequential
URL measurements, we could consider an alternative design where
we space endpoint measurements in time to avoid rate limiting.


## 2. Measurement algorithm

A websteps client measures URLs starting from an initial URL and
follows redirects.

Each redirect
counts as a subsequent step. For example, if `http://c.com` redirects
to `http://a.c.com` for an endpoint and `http://b.c.com` for
another, both `http://a.c.com` and `http://b.c.com` count as distinct
next steps.

Each step produces DNS and endpoint measurements related to a URL.

### 2.1. Data types

Websteps produces a measurement result that in pseudo-Python looks like the following:

```Python
class TestKeys:
    def __init__(self):
        self.url = ""
        self.steps = List[SingleStepMeasurement] = []
        self.flags = 0
```

where:

- `url` is the initial URL;

- `steps` contains the result of each step;

- `flags` is a bitmask where each bit represents a kind of anomaly.

The result of each step looks like the following:

```Python
class SingleStepMeasurement:
    def __init__(self):
        self.probe_initial = URLMeasurement()
        self.th: Optional[THResponse] = None
        self.probe_additional: List[EndpointMeasurement] = []
        self.analysis = Analysis()
        self.flags = 0
```

where:

- `probe_initial` contains the client's initial measurement of
this step's URL;

- `th` contains the response from the test helper (TH) if any;

- `probe_additional` contains additional measurements performed by
the client based on the TH results;

- `analysis` contains the results of analyzing `probe_initial`,
`th`, and `probe_additional`;

- `flags` is a bitmask where each bit represents a kind of anomaly.

The `URLMeasurement` structure looks like this:

```Python
class URLMeasurement:
    def __init__(self):
        self.id = 0
        self.endpoint_ids: List[int] = []
        self.options = Options()
        self.url = SimpleURL()
        self.cookies: List[Cookies] = []
        self.dns: List[DNSLookupMeasurement] = []
        self.endpoints: List[EndpointMeasurement] = []
```

where:

- `id` uniquely identifies this structure within the `TestKeys`;

- `endpoint_ids` lists all end `EndpointMeasurement` IDs containing
redirects that caused this `URLMeasurement`;

- `options` contains options used to perform this measurement;

- `url` is the URL we measured;

- `cookies` contains the list of cookies we use;

- `dns` contains all the DNS measurements we performed;

- `endpoint` contains all the endpoint measurements we performed.

A `SimpleURL` looks like this:

```Python
class SimpleURL:
    def __init__(self):
        self.scheme = ""
        self.host = ""
        self.path = ""
        self.query = ""
```

where the field names are self-explanatory.

A `Cookie` looks like this:

```Python
class Cookie:
    def __init__(self):
        self.name = ""
        self.value = ""
```

where the field names are self-explanatory.

The `Options` structure contains several options that influence
various websteps algorithms. The specific subset of options that
influence the top-level algorithms is like this:

```Python
class Options:
    def __init__(self):
        self.do_not_follow_http_and_https = False
        self.greedy_mode = True
        self.max_crawler_depth = 3
        # ... plus other options that we will describe later ...
```

where:

- `do_not_follow_http_and_https` indicates whether we should measure
HTTP and HTTPS regardless of the URL's scheme;

- `greedy_mode` controls whether a websteps client should stop after
a step has found any anomalous results;

- `max_crawler_depth` tells the redirect queue about the maximum number of steps to allow.

We follow HTTP and HTTPS for the initial step. Doing that captures the
user experience when they type the URL in the browser without specifying
the URL name. We keep doing that for subsequent steps as long as the
URL scheme is HTTP. Successful HTTPS measurements provide a solid oracle to
determine the legitimacy of DNS lookup results.

Setting a maximum crawler depth and enabling greedy mode ensures that we
strike a balance between the in-depth investigation of the redirects of a
single initial URL and exploring all the URLs to be tested within a
measurement session. We chose to stop after three steps because of our
previous analysis on the redirect depth of URLs in the test list in
[probe#1727](https://github.com/ooni/probe/issues/1727#issuecomment-891815605).

The `Analysis` structure looks like this:

```Python
class Analysis:
    def __init__(self):
        self.dns = AnalysisDetails()
        self.endpoint = AnalysisDetails()
        self.th = AnalysisDetails()
```

where:

- `dns` contains the results of comparing each DNS lookup performed by
the client to an equivalent lookup performed by the TH;

- `endpoint` contains the results of comparing each endpoint measurement
performed by the client to an equivalent one performed by the TH;

- `th` contains the results of comparing TH measurements using IP
addresses discovered by the client to the ones using addresses
discovered by the TH.

We provide more details on the purpose of these comparisons in
the analysis section of this document.

The `AnalysisDetails` structure looks like this:

```Python
class AnalysisDetails:
    def __init__(self):
        self.id = 0
        self.refs: List[int] = []
        self.flags = 0
```

where:

- `id` uniquely identifies this structure within the `TestKeys`;

- `refs` contains the ID of the DNS or endpoint or TH results
used to produce this analysis result;

- `flags` is a bitmask where each bit represents a kind of anomaly.

We discuss `DNSLookupMeasurement` and `EndpointMeasurement` more
in detail in subsequent sections. However, it is worth mentioning
that their common structure is the following:

```Python
class DNSLookupOrEndpointMeasurement:
    def __init__(self):
        self.id = 0
        # ... fields specific to the kind of measurement
```

where `id` uniquely identifies this structure within the `TestKeys`.

Because each relevant data structure has a unique ID within the
`TestKeys,` it is easy to unpack a websteps measurement to a set of
data structures referencing each other.


### 2.2 Top-level algorithm

We need to introduce a structure called the `RedirectQueue`. This
structure contains:

1. past `URLMeasurement`s;

2. future `URLMeasurement`s.

Past ` URLMeasurement`s allow us to determine whether a future `URLMeasurement` is
redundant because we already performed such a measurement. Future `URLMeasurement`s
derive from redirects.

Two `URLMeasurement`s are equal if they have the same URL and cookies names.
We must include cookies when comparing URLs because the test
list includes URLs that redirect to themselves, and the redirect
only differs in the list of cookies (see
[probe#1727](https://github.com/ooni/probe/issues/1727#issuecomment-892518225)).

The top-level algorithm looks like this:

```Python
def steps(url: string, options: Options) -> TestKeys:
    tk = TestKeys()
    q = RedirectQueue(options)
    q.append(URLMeasurement.from_url(url, options))
    while True:
        if q.is_empty() or q.max_crawler_depth_exceeded():
            return tk
        um: URLMeasurement = q.pop()
        ssm: SingleStepMeasurement = step(um)
        q.remember_visited_urls(ssm.probe_initial, ssm.probe_additional)
        redirects: List[URLMeasurement] = ssm.redirects()
        q.append(redirects)
        if options.greedy_mode and ssm.found_any_anomaly():
            break
```

where:

- `remember_visited_urls` registers all the `probe_initial` and
`probe_additional` measurements as already visited URLs;

- `q.append(redirects)` inserts future redirects into the queue.

Clients MAY avoid analyzing their results
and defer this analysis to the OONI pipeline. However, not performing
such an analysis prevents a client from implementing the greedy mode.


### 2.3. Single step measurement

This algorithm measures a single URL without following redirects. Its
input is an `URLMeasurement`, and its output is a `SingleStepMeasurement`.

The algorithm consists of the following steps:

1. perform DNS lookups;

2. measure endpoints deriving from DNS lookups;

3. if the client implements HTTP3, search for `h3` in `Alt-Svc` response
headers and measure the related endpoints;

4. query the TH;

5. measure additional endpoints discovered by the TH;

6. if the client implements analysis, analyze the measurements results.

Before showing a pseudo-Python implementation, we need to define
the following support structures and concepts:

- `DNSLookupPlan`

- `URLAddressList`

- `EndpointPlan`

The `DNSLookupPlan` is a plan describing how to perform a DNS lookup. In
pseudo-Python, this structure looks like this:

```Python
class DNSLookupPlan:
    def __init__(self):
        self.domain = ""
        self.lookup_type = ""
        self.options = Options()
        self.resolver_network = ""
        self.resolver_address = ""
```

where:

- `domain` is the domain to resolve;

- `lookup_type` is the type of lookup (see below);

- `options` contains the options to use;

- `resolver_network` and `resolver_address` identify the
kind of resolver to use and its address (see below);

We define the following types of lookup:

| Name | Description |
| -- | -- |
| https | HTTPSSvc lookup |
| getaddrinfo | A and AAAA lookups |
| ns | NS lookup |
| reverse | reverse (i.e., PTR) lookup |

We define the following types of resolvers:

| Network | Address |  Description |
| -- | -- | -- |
| doh | `<url>` | DNS over HTTPS |
| dot | `"<addresss>:<port>"` | DNS over TLS |
| system | `""` | System resolver (i.e., `getaddrinfo`) |
| tcp | `"<address>:<port>"` | DNS over TCP |
| udp | `"<address>:<port>"` | UDP over UDP |

When `<address>` is IPv6, it is quoted using `[` and `]` (e.g., `[::1]`).

Clients MUST support `getaddrinfo` lookup types using the `system` resolver. All
other kinds of lookups and resolvers are OPTIONAL.

The `URLAddressList` is a list of `URLAddress` structures where each
structure describes what we know about an IP address. In pseudo-Python,
`URLAddress` looks like this:

```Python
class URLAddress:
    def __init__(self):
        self.address = ""
        self.flags = 0
```

where:

- `address` is an IPv4 or IPv6 address;

- `flags` contains the following set of flags:

| Flag | Description |
| -- | -- |
| `ALREADY_TESTED_HTTP` | We (or the TH) already tested this address with HTTP. |
| `ALREADY_TESTED_HTTPS` | We (or the TH) already tested this address with HTTPS. |
| `ALREADY_TESTED_HTTP3` | We (or the TH) already tested this address with HTTP. |
| `SUPPORTS_HTTP3` | We know this address supports HTTP3. |
| `SYSTEM_RESOLVER` | We learned this address using the system resolver. |

The `EndpointPlan` is a structure describing an endpoint measurement. In
pseudo-Python this structure looks like this:

```Python
class EndpointPlan:
    def __init__(self):
        self.address = ""
        self.cookies: List[Cookie] = []
        self.domain = ""
        self.network = ""
        self.options = Options()
        self.url = SimpleURL()
```

where:

- `address` is the endpoint address (e.g., `8.8.8.8:443`);

- `cookies` contains the cookies to use;

- `domain` is the domain associated with the endpoint;

- `network` is either `"tcp"` or `"quic"`;

- `options` contains the options;

- `url` is the URL of the endpoint.

The single-step measurement algorithm looks like this:

```Python
def step(um: URLMeasurement) -> SingleStepMeasurement:

    # 1. perform DNS lookups
    dns_plans = new_dns_lookup_plans(um)
    for m in dns_lookups(dns_plans):
        um.dns.append(m)

    # 2. measure endpoints
    epnt_plans = new_endpoint_plans(
        um, new_url_address_list(um.dns, um.endpoint))
    for m in measure_endpoints(epnt_plans):
        um.endpoint.append(m)

    # 3. measure endpoints discovered using Alt-Svc
    if HAVE_HTTP3_SUPPORT:
        http3_only_plans = new_endpoint_plans(
            um, new_url_address_list(um.dns, um.endpoint), flags=ONLY_HTTP3)
        for m in measure_endpoints(http3_only_plans):
            um.endpoint.append(m)

    # 4. build single step measurement
    ssm = SingleStepMeasurement()
    ssm.probe_initial = um

    # 5. query the TH
    ssm.th = th_round_trip(um.dns, epnt_plans)

    # 6. measure endpoints discovered by the TH
    probe_addrs = new_url_address_list(um.dns, um.endpoint)
    th_addrs = new_url_address_list(th.dns, th.endpoint)
    th_only_addrs = url_address_list_diff(th_addrs, probe_addrs)
    epnt_plans = new_endpoint_plans(um, th_only_addrs, flags=MEASURE_AGAIN)
    for m in measure_endpoints(epnt_plans):
        ssm.probe_additional.append(m)

    # 7. performs local analysis
    if HAVE_ANALYSIS_SUPPORT:
        ssm.analysis = perform_analysis(ssm)

    return ssm
```

Here are some comments on the above pseudo-code snippet:

1. HTTP3 support and local analysis are OPTIONAL;

2. the TH round trip only depends on the client's DNS lookup
and the client's endpoint plan; therefore, it could (and SHOULD)
run in parallel with the endpoint measurements;

3. we will discuss `new_url_address_list` more in-depth later
but it is worth mentioning that we need the `MEASURE_AGAIN`
flag when testing the TH endpoints because the `th_only_addrs`
list contains addresses that result as already measured (by the
TH) so we need to force the client to measure them _again_.

In the following sections, we are going to provide more information on
DNS measurements, URL address lists, and endpoint measurements.


#### 2.3.1 new_dns_lookup_plans

Clients MUST always include a lookup using the "system" resolver into the plan.
They SHOULD also include a well-known UDP resolver (e.g., `8.8.8.8:53/udp`).  By
including a UDP resolver, we get a clearer picture of DNS censorship.

If clients choose to select a UDP resolver at random among a list of candidates, they
SHOULD consistently use such a resolver for all the websteps steps.


#### 2.3.2. new_url_address_list

This algorithm takes in input DNS and endpoint measurements, and returns
an URL address list. Its pseudo-Python implementation looks like this:

```Python
def new_url_address_list(
    dns: List[DNSLookupMeasurement],
    endpoints: List[EndpointMeasurement],
) -> List[URLAddress]:
    uniq: OrderedDict[str, int] = OrderedDict()

    # 1. process DNS lookup measurements
    for dlm in dns:
        flags = 0
        if dlm.lookup_type == "https" and dlm.has_http3_alpn():
            flags |= SUPPORTS_HTTP3
        if dlm.resolver_network == "system":
            flags |= SYSTEM_RESOLVER
        for addr in dlm._addresses():
            uniq.setdefault(addr, 0)
            uniq[addr] |= flags

    # 2. process endpoint measurements
    for em in endpoints:
        addr = em.ip_address()
        flags = 0
        if em.is_http_measurement():
            flags |= ALREADY_TESTED_HTTP
        if em.is_https_measurement():
            flags |= ALREADY_TESTED_HTTPS
        if em.is_http3_measurement():
            flags |= ALREADY_TESTED_HTTP3
        if em.has_http3_alt_svc():
            flags |= SUPPORTS_HTTP3
        uniq.setdefault(addr, 0)
        uniq[addr] |= flags

    # ...
```

Here are some notes on the above snippet:

1. we include the case in which we learn about HTTP3 support
from HTTPSSvc queries for completeness, even though clients
SHOULD NOT query for HTTPSSvc (at least until this functionality
has been standardized);

2. we omit the trivial part of the algorithm where we transform
the `uniq` map to a list of `URLAddress`.

Clients MUST use the system resolver and SHOULD also use a UDP resolver. In such
a case, they MUST rearrange the result of `new_url_address_list` before
returning it to the caller to interleave IP addresses resolved using
the system resolver with addresses resolved using the UDP one.

In pseudo-Python:

```Python
def _rearrange_addresses(ual: List[URLAddress]) -> List[URLAddress]:
    system = [ua for ua in ual if (ua.flags & SYSTEM_RESOLVER) != 0]
    other = [ua for ua in ual if (ua.flags & SYSTEM_RESOLVER) == 0]
    out: List[URLAddress] = []
    si, oi = 0, 0
    while len(out) < len(system) + len(other):
        if si < len(system):
            out.append(system[si])
            si += 1
        if oi < len(other):
            out.append(other[oi])
            oi += 1
    return out
```

The reason why we use an ordered map in `new_url_address_list` and we
`_rearrange_addresses` is because we want to ensure we test the IP
addresses of both resolvers in the presence of constraints on the maximum
number of testable IP addresses per step (on which we will focus
in the next section).


#### 2.3.3 new_endpoint_plans


This algorithm takes in input an `URLMeasurement`, an `URLAddress` list,
and optional flags and returns an `EndpointPlan` list. A trivial
implementation of this algorithm would generate all the possible
endpoints for the given `URLMeasurement`. However, we introduce the
following constraints:

```Python
class Options:
    def __init__(self):
        # ... other options introduced before
        self.max_addresses_per_family = 2
```

where `max_addresses_per_family` limits the maximum number of addresses
per family that `new_endpoint_plans` can emit.

Limiting the maximum number of addresses per family allows us to
compromise between measuring a single step in depth and
measuring subsequent steps or other URLs.

If a client only uses the system resolver, then `max_addresses_per_family`
may be as small as `1`. However, if a client also uses a UDP resolver,
`max_addresses_per_family` SHOULD NOT be smaller than `2`. Because we
`_rearrange_addresses`, a value of `2` for `max_addresses_per_family`
ensures that we test one IP address discovered by the system resolver and
one IP address discovered by the UDP resolver.

The `new_endpoint_plans` algorithm honors the following flags:

1. `EXCLUDE_BOGONS`: this flag tells the endpoint measurement planner to
exclude bogons from the planning. We only use this flag in the TH for obvious reasons.

2. `ONLY_HTTP3`: this flag tells the endpoint planner to generate a plan for
measuring HTTP3 endpoints only. The client uses this flag to measure the endpoints
it discovered to support HTTP3 via `Alt-Svc` headers.

3. `INCLUDE_ALL`: this flag disables the `max_addresses_per_family` restriction.

4. `MEASURE_AGAIN`: this flag forces the planner to measure endpoints that the
client or the TH have already measured.

Here's the algorithm's pseudocode:

```Python
def new_endpoint_plans(um: URLMeasurement, ual: List[URLAddress],
                       flags: int) -> List[EndpointPlan]:
    again = (flags & MEASURE_AGAIN) != 0
    counter: Dict[str, set(str)] = {}
    max_addrs = um.options.max_addresses_per_family
    out: List[EndpointPlan] = []
    for addr in addrs:
        if (flags & EXCLUDE_BOGONS) != 0 and is_bogon(addr):
            continue
        if is_loopback(addr):
            continue
        family = "AAAA" if is_ipv6(addr) else "A"
        counter.setdefault(family, set())
        if (flags & INCLUDE_ALL) == 0 and len(counter[family]) >= max_addrs:
            continue
        if (flags & ONLY_HTTP3) == 0:
            if um.is_http() and (not addr.already_tested_http() or again):
                out.append(_new_endpoint_plan("tcp", addr.address, "http"))
                counter[family].add(addr.address)
            if self.is_https() and (not addr.already_tested_https() or again):
                out.append(_new_endpoint_plan("tcp", addr.address, "https"))
                counter[family].add(addr.address)
        if self.is_https() and addr.supports_http3():
            if not addr.already_tested_http3() or again:
                out.append(_new_endpoint_plan("quic", addr.address, "https"))
                counter[family].add(addr.address)
        return out
```

Note that we always exclude the loopback address from the planning. Doing that
is safe because there is no legitimate case in which it makes sense to follow a
redirect to the localhost.


#### 2.3.4. DNS lookup measurements

The client executes a list of DNSLookupPlans that produces a list of
DNSLookupMeasurements. Every entry in the plan produces a measurement.

The DNSLookupMeasurement looks like this:

```Python
class DNSLookupMeasurement:
    def __init__(self):
        self.id = 0
        self.lookup = DNSLookupEvent()
        self.round_trips: List[DNSRoundTripEvent] = []
```

where:

- `id` uniquely identifies this structure within the `TestKeys`;

- `lookup` contains the results of the lookup operation (i.e., the
resolved IP addresses, or the failure that occurred);

- `round_trips` contains individual DNS round trips (for resolvers
for which we can observe them).

A DNSLookupEvent is like this:

```Python
class DNSLookupEvent:
    def __init__(self):
        self.alpns: List[str] = []
        self.addresses: List[str] = []
        self.cname = ""
        self.domain = ""
        self.failure = ""
        self.finished = ""
        self.lookup_type = ""
        self.ns: List[str] = []
        self.ptr: List[str] = []
        self.resolver_address = ""
        self.resolver_network = ""
        self.started = ""
```

where:

- `alpns` contains the discovered ALPNs (only applicable for the `https` lookup type);

- `addresses` contains the discovered addresses for `getaddrinfo` and `https` lookup types;

- `cname` contains the `CNAME` (if we managed to discover it);

- `domain` is the domain we queried for;

- `failure` is an empty string on success and an OONI error string on failure;

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `lookup_type` is the type of lookup and should be one of `getaddrinfo`,
`https` (for `HTTPSSvc`), `ns` and `reverse`;

- `ns` contains the result of `ns` queries;

- `ptr` contains the result of `reverse` lookups;

- `resolver_address` is the address of the resolver;

- `resolver_network` is the network of the resolver;

- `started` is when we started the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`.

The DNSRoundTrip event looks like this:

```Python
class DNSRoundTripEvent:
    def __init__(self):
        self.failure = ""
        self.finished = ""
        self.query = ""
        self.reply = ""
        self.resolver_address = ""
        self.resolver_network = ""
        self.started = ""
```

where:

- `failure` is an empty string on success and an OONI error string on failure;

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `query` contains the raw bytes of the query we sent encoded as `base64`;

- `reply` contains the raw bytes of the reply we received encoded as `base64` (or
is empty if we did not receive any reply);

- `resolver_address` is the address of the resolver;

- `resolver_network` is the network of the resolver;

- `started` is when we started the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`.

Underlying resolvers invoked with an IP address as the domain to resolve MUST return a
fake DNS lookup including such an IP address. This requirement ensures that we
correctly handle URLs containing IP addresses rather than domain names.

Clients SHOULD include data on each DNS round trip when using UDP resolvers.

All measurements SHOULD use a monotonic clock, where possible.

Clients MAY use an in-memory DNS cache to avoid repeating the DNS lookups
performed in previous steps. In such a case, the cache SHOULD return IP addresses in
the same order as the original lookup to consistently test the same addresses.

#### 2.3.5. Endpoint measurements

The client executes a list of EndpointPlans that produces a list of
EndpointMeasurements. Every entry in the plan produces a measurement.

**EDITOR'S NOTE**: here we should mention options controlling
the parallelism. We should also add a section discussing the
impact of parallelism on measurements quality. We should discuss,
in particular, the potential impact of policer devices.

If the URL scheme is HTTP, the client performs a TCP connect followed by
a GET request using the configured headers and cookies.

If the URL scheme is HTTPS and the protocol is TCP, the client performs
a TLS handshake after the TCP connect and before the GET request.

When the protocol is QUIC, the client performs a QUIC handshake followed
by a GET request with the configured headers and cookies.

The following options apply to endpoint measurements:

```Python
class Options:
    def __init__(self):
        # ... other options introduced before
        self.max_http_response_body_snapshot_size = 0
        self.max_https_response_body_snapshot_size_connectivity = 0
        self.max_https_response_body_snapshot_size_throttling = 0
```

where:

- `max_http_response_body_snapshot_size` controls the maximum amount of bytes
downloaded when the URL scheme is `http:`;

- `max_https_response_body_snapshot_size_connectivity` controls the maximum
amount of bytes downloaded when the URL scheme is `https:` and the URL path is
`/` or empty;

- `max_https_response_body_snapshot_size_throttling` controls the maximum amount
of bytes downloaded when the URL scheme is `https:` and the URL path is neither
`/` nor empty.

For `http:` URLs, we download a sizable amount of the webpage to allow OONI's
data processing pipeline to continue hunting for blockpages.  Based on
[probe#1727](https://github.com/ooni/probe/issues/1727#issuecomment-892562961),
`1<<19` is enough to download most bodies in the canonical test list.

The downloaded body size is small for `https:` without a specific URL path
to avoid wasting bandwidth. We know people added those URLs in the test list
to check for connectivity.

For `https:` with a specific URL path, people added those URLs to check for
throttling. So, we download a larger body and collect network events to
detect cases of extreme throttling. If a client
does not implement collecting network events, it MAY choose to use a smaller
body size for `https:` URLs with paths.

An EndpointMeasurement contains the following fields:

```Python
class EndpointMeasurement:
    def __init__(self):
        self.id = 0
        self.url = SimpleURL()
        self.network = ""
        self.address = ""
        self.options = Options()
        self.orig_cookies: List[Cookie] = []
        self.failure = ""
        self.failed_operation = ""
        self.finished = ""
        self.new_cookies: List[Cookie] = []
        self.location: Optional[SimpleURL] = None
        self.http_title = ""
        self.network_event: List[NetworkEvent] = []
        self.tcp_connect: Optional[NetworkEvent] = None
        self.quic_tls_handshake: Optional[QUICTLSHandshake] = None
        self.http_round_trip: Optional[HTTPRoundTripEvent] = None
```

where:

- `id` uniquely identifies this structure within the `TestKeys`;

- `url` is the URL we measured;

- `network` is the endpoint network (`"tcp"` or `"quic"`);

- `address` is the endpoint address (e.g., `"8.8.8.8:443"`);

- `options` contains the options;

- `orig_cookies` contains the cookies used for measuring;

- `failure` is an empty string on success and an OONI error string on failure;

- `failed_operation` is the empty string or the operation that
failed (one of `"tcp_connect"`, `"tls_handshake"`, `"quic_handshake"`,
and `"http_round_trip"`);

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `new_cookies` contains the original cookies plus the new
cookies obtained by the HTTP responses;

- `location` is either not set or contains the `Location` URL;

- `http_title` is either empty or contains the title of the downloaded webpage;

- `network_event` contains sockets read and write events (collecting these
events is OPTIONAL);

- `tcp_connect` is either not set or contains the TCP connect event;

- `quic_tls_handshake` is either not set or contains the QUIC or TLS handshake event;

- `http_round_trip` is either not set or contains the HTTP round trip event.

The NetworkEvent structure is like this:

```Python
class NetworkEvent:
    def __init__(self):
        self.count = 0
        self.failure = ""
        self.finished = ""
        self.network = ""
        self.operation = ""
        self.remote_addr = ""
        self.started = ""
```

where:

- `count` is the number of bytes transferred;

- `failure` is an empty string on success and an OONI error string on failure;

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `network` is the endpoint's network (`"tcp"` or `"udp"`);

- `operation` is one of `"read"`, `"read_from"`, `"write"`, `"write_to"`, and `"connect"`;

- `remote_addr` is the remote endpoint's address (e.g., `"8.8.8.8:443"`);

- `started` is when we started the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`.

The QUICTLSHandshake structure looks like this:

```Python
class QUICTLSHandshake:
    def __init__(self):
        self.alpn: List[str] = []
        self.cipher_suite = ""
        self.failure = ""
        self.finished = ""
        self.negotiated_proto = ""
        self.network = ""
        self.peer_certs: List[str] = []
        self.remote_addr = ""
        self.sni: str = ""
        self.skip_verify = False
        self.started = ""
        self.tls_version = ""
```

where:

- `alpn` contains the list of offered ALPNs;

- `cipher_suite` contains the negotiated cipher suite;

- `failure` is an empty string on success and an OONI error string on failure;

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `negotiated_proto` contains the ALPN-negotiated protocol;

- `network` is the endpoint network (`"tcp"` or `"udp"`);

- `peer_certs` contains zero or more DER-encoded certificates encoded using base64;

- `remote_addr` is the remote endpoint's address (e.g., `"8.8.8.8:443"`);

- `sni` contains the SNI;

- `skip_verify` is true when we are not verifying the certificate;

- `started` is when we started the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `tls_version` is the negotiated TLS version.

HTTPRoundTripEvent is like this:

```Python
class HTTPRoundTripEvent:
    def __init__(self):
        self.failure = ""
        self.finished = ""
        self.method = ""
        self.request_headers = HTTPHeader()
        self.response_body = ""
        self.response_body_is_truncated = False
        self.response_body_length = 0
        self.response_headers = HTTPHeader()
        self.started = ""
        self.status_code = 0
        self.transport = ""
        self.url: str = ""
```

where:

- `failure` is an empty string on success and an OONI error string on failure;

- `finished` is the time when we finished the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `method` is the request method;

- `request_headers` contains the request headers;

- `response_body` is the response body encoded using base64;

- `response_body_is_truncated` indicates whether the response body only
contains a snapshot of the original body;

- `response_body_length` contains the length of `response_body`;

- `response_headers` contains response headers;

- `started` is when we started the measurement expressed as `%Y-%m-%dT%H:%M:%S.%fZ`;

- `status_code` is zero or contains the status code;

- `transport` is either `"tcp"` or `"quic"`;

- `url` is the URL for this measurement.

**EDITOR'S NOTE**: here we should discuss HTTPHeader's structure.

Bandwidth constrained clients MAY enforce a maximum snapshot size of zero for
HTTP, HTTPS connectivity, and HTTPS throttling request, thus saving lots of
bandwidth because they do not fetch the body. A client implementation SHOULD
NOT download more bytes than the configured snapshot size.


#### 2.3.6. th_round_trip

**EDITOR'S NOTE**: the current implementation of the TH protocol is slightly
different: it uses PascalCase, has a more complex representation of cookies, and
the endpoint paths are slightly different. We should fix these inconsistencies
in the implementations before making this spec final.

**EDITOR'S NOTE**: this section should mention that the TH
attempts to opportunistically extract CNAMEs from A/AAAA
lookups and performs reverse lookups of the non-bogon addresses
discovered by itself or by the client.

The test helper (TH) exposes two endpoints:

1. `https://$domain/api/v1/websteps/http`

2. `wss://$domain/api/v1/websteps/websocket`

The former endpoint is a web API, and the latter uses WebSocket.

The check-in API will provide clients with a list of available
TH URLs. Clients SHOULD attempt all available URLs before giving up. They
SHOULD also remember which URLs worked and attempt using them first in
subsequent round trips with the TH.

For both web and WebSocket endpoints, clients send the following THRequest:

```Python
class THRequest:
    def __init__(self):
        self.url = ""
        self.options = Options()
        self.cookies: List[Cookies] = []
        self.plan: List[THRequestEndpointPlan] = []
```

where:

- `url` is the URL we are measuring;

- `options` contains the options;

- `cookies` contains the cookies used in this step;

- `plan` is a list of simplified endpoint plans.

A THRequestEndpointPlan looks like this:

```Python
class THRequestEndpointPlan:
    def __init__(self):
        self.network = ""
        self.address = ""
        self.url = SimpleURL()
```

where fields have the same semantics as `EndpointPlan`.

The HTTP API receives a THRequest as the JSON body of a POST request and
replies with a THResponse, which looks like this:

```Python
class THResponse:
    def __init__(self):
        self.still_running = False
        self.dns: List[DNSLookupMeasurement] = []
        self.endpoint: List[EndpointMeasurement] = []
```

where:

- `still_running` is only used by WebSocket endpoints (see below);

- `dns` contains the TH's DNS measurements;

- `endpoint` contains the TH's endpoint measurements.

The WebSocket API sends a THRequest as a WebSocket text message. While performing the
measurement, the TH will periodically reply with text messages containing a THResponse
where `still_running` is true. When done, the TH will reply with a text
message containing a THResponse with `still_running` set to false. Using WebSocket
increases the chance of keeping the connection alive because there is traffic in
a context where middleboxes aggressively terminate idle connections, and clients SHOULD
therefore prefer using WebSocket.

The TH MUST NOT include HTTP bodies in its THResponse. The client MUST import
TH measurements by updating all the IDs to assign to each measurement IDs that
are consistent with the numbering used locally by the client. The client SHOULD
NOT modify the started and finished fields of measurements in the THResponse
because they provide performance information from the point of view of the TH.

The TH implements this algorithm for serving HTTP requests:

```Python
def service_th_request_with_http(thr: THRequest) -> Tuple[THResponse, int]:
    if not thr_is_valid(thr.options):
        return (THResponse(), 400)
    um = URLMeasurement.from_url(thr.url)
    dns_plans = new_dns_lookup_plans(um, resolvers=DEFAULT_DOH_RESOLVERS)
    for m in dns_lookups(dns_plans):
        um.dns.append(m)
    epnt_plans = new_endpoint_plans(um, new_url_address_list(um.dns, [], flags=EXCLUDE_BOGONS))
    epnt_plans = patch_endpoint_plans(epnt_plans, thr)
    for m in measure_endpoints(epnt_plans):
        um.endpoint.append(m)
    http3_plans = new_endpoint_plans(um, new_url_address_list(
        [], um.endpoint, flags=EXCLUDE_BOGONS | ONLY_HTTP3,
    ))
    for m in measure_endpoints(http3_plans):
        um.endpoint.append(m)
    out = THResponse()
    out.dns = um.dns
    out.endpoint = um.endpoint
    return (out, 200)
```

Here are some notes on the above pseudo-code:

1. the TH MUST validate incoming options and reject all the options that
are not compatible with its configuration (e.g., too large body snapshots, or
too many IP addresses per address family);

2. the TH MUST use one (or more) DoH resolvers to exclude the possibility
of DNS censorship in the network in which the TH is running;

3. `patch_endpoint_plans` MUST:

    3.1. include all client measured IP addresses except bogons;

    3.2. only include 1-2 extra IP addresses it discovered and the client is not aware
	of, giving the client a chance to testing
    additional, legitimate IP addresses.

The algorithm implemented for WebSocket requests is the same
except that it also sends periodic `still_running` messages to the client.

Clients that want to measure all endpoints for a given URL MUST
space their operations in time and SHOULD NOT request the TH
to measure all the endpoints in a single request because that
MAY cause the TH to trigger rate limiting. The TH MUST protect
itself against this possibility by limiting the max number of
addresses per address family.

A TH implementation SHOULD implement caching to avoid performing
repeated DNS/endpoint measurements in a short time frame.

The following fields uniquely identify a DNS plan or measurement for caching:

- domain

- lookup_type

- resolver_network

- resolver_address

In the same vein, the following fields uniquely identify an
endpoint plan or measurement:

- normalized URL

- network

- address

- options

- cookies names

The TH SHOULD NOT cache measurements for more than 15 minutes. The TH
SHOULD periodically prune the cache to eliminate expired entries.


## 3. Archival data format


The archival data format is the one used to submit OONI measurement. This
data format complies with existing OONI data formats.

The TestKeys type serializes to this JSON type (we provide the rule
used to perform the conversion as an inline comment where `self`
is a reference to the type we are converting to the archival data format
and we use Python or JavaScript syntax to express the transformation):

```JavaScript
/* ArchivalTestKeys = */ {
    "url": "",   // = self.url
    "steps": [], // = [step.to_archival() for step in self.steps]
    "flags": 0   // = self.flags
}
```

The SingleStepMeasurement type serializes to:

**EDITOR'S NOTE**: the current data format explodes `probe_initial` into the
single-step-measurement, but this is probably a mistake because it seems easier to read it as a sub-measurement container.

```JavaScript
/* ArchivalSingleStepMeasurement = */ {
    "probe_initial": {}      // = self.probe_initial.to_archival()
    "th": null,              // = self.th?.to_archival()
    "probe_additional": [],  // = [e.to_archival() for e in self.probe_additional]
    "analysis": {},          // = self.analysis.to_archival()
    "flags": 0               // = self.flags
}
```

The Analysis type serializes to:

```JavaScript
/* ArchivalAnalysis = */ {
    "dns": []        // = [d.to_archival() for d in self.dns]
    "endpoint": [],  // = [e.to_archival() for e in self.endpoint]
    "th": []         // = [t.to_archival() for t in self.th]
}
```

where AnalysisDetails trivially serializes to:

```JavaScript
/* ArchivalAnalysisDetails = */ {
    "id": 0,     // = self.id
    "refs": [],  // = self.refs
    "flags": 0   // = self.flags
}
```

The URLMeasurement data type serializes to:

```JavaScript
/* ArchivalURLMeasurement = */ {
    "id": 0,               // = self.id
    "endpoint_ids": [],    // = self.endpoint_ids
    "options": {},         // = self.options.__dict__
    "url": "",             // = str(self.url)
    "cookies_names": "",   // = [c.name for c in self.cookies]
    "dns": [],             // = [d.to_archival() for d in self.dns]
    "endpoint": [],        // = [e.to_archival() for e in self.endpoint]
}
```

The SimpleURL type serializes to string as follows:

```Python
class SimpleURL:
    def __str__(self) -> str:
        return urlunparse((self.scheme, self.host, self.path, "", self.query, "")).geturl()
```

The DNSLookupMeasurement serializes to:

```JavaScript
/* ArchivalDNSLookupMeasurement = */ {
    "id": 0,                 // = self.id
    "domain": "",            // = self.lookup.domain
    "resolver_network": "",  // = self.lookup.resolver_network
    "resolver_address": "",  // = self.lookup.resolver_address
    "failure": null,         // = self.lookup?.failure
    "addresses": [],         // = self.lookup.addresses
    "queries": []            // = ...
}
```

where the `queries` field serialization is compatible with
the `df-002-dnst` OONI data format.

The EndpointMeasurement serializes to:

```JavaScript
/* ArchivalEndpointMeasurement = */ {
    "id": 0,                     // = self.id
    "url": "",                   // = str(self.url)
    "network": "",               // = self.network
    "address": "",               // = self.address
    "cookies_names": [],         // = [c.name for c in self.cookies]
    "failure": null,             // = (self.failure === "") ? null : self.failure
    "failed_operation": null,    // = (self.failed_operation === "") ? null : self.failed_operation
    "status_code": 0,            // = self.http_round_trip?.status_code
    "location": "",              // = str(self?.location)
    "body_length": 0,            // = self.http_round_trip?.response_body_length
    "title": "",                 // = self.http_title
    "network_events": [],        // = ...
    "tcp_connect": null,         // = ...
    "quic_tls_handshake": null,  // = ...
    "http_round_trip": null,     // = ...
}
```

where:

- `network_events` is compatible with `df-008-netevents`;

- `tcp_connect` is compatible with `df-004-tcpt`;

- `quic_tls_handshake` is compatible with `df-006-tlshandshake`;

- `http_round_trip` is compatible with `df-001-httpt`.


## 4. Data analysis

Websteps data analysis could run either on the client or the OONI
data processing pipeline. We could either consider a TestKeys data
structure at a time or a set of them. In the latter case, it is possible
to make additional inferences by observing IP addresses and web pages
common to too many domain names. Those IP addresses and web pages
are great blockpage candidates.

However, in this specification, we will not focus on this kind
of analysis, which is common to all OONI experiments. Instead, we are
going to focus on websteps-specific data analysis algorithms. We
will also focus on processing a single TestKeys entry at a time
without considering previous or future entries.

When the pipeline runs websteps data analysis, it uses the
archival data format. The websteps client SHOULD 
preferably use webstep's data format, which is easier to
process because it is more regular and has fewer nullable fields.

### 4.1. SingleStepMeasurement analysis

We define three analysis algorithms:

1. analysis of individual client DNS measurements and
comparison with matching TH measurements;

2. analysis of individual client endpoint measurements and
comparison with matching TH measurements;

3. comparison of TH measurements using IP addresses
resolved by the client versus TH measurements using
TH-resolved IP addresses.

The result of the first algorithm fills the `dns` field
of the TestKeys.Analysis structure. The second
algorithm fills the `endpoint` field. While the third
one adds records to the `th` field.

Before discussing these three algorithms, we need
to define the analysis flags. These flags are bits
inside a bitmask. We use a bitmask because it allows
for trivially composing the results of a specific
analysis with the other analysis results by using
the bitwise OR operator.

### 4.2. Blocking flags


We use a 64-bit integer for representing the flags. We
split the 64-bit space into two sub-spaces as follows:

```
  0                15               31
  +----------------+----------------+
  |          public flags           |
  +----------------+----------------+
  |             reserved            |
  +----------------+----------------+
```

We use the public flags to define blocking conditions to
report, and we use the reserved flags to indicate finer-grained blocking 
conditions or detected (and avoided) false
positives. We will not change the public
flags over time, while we may occasionally change the
reserved flags. This design gives us space to experiment
with websteps potentialities without committing all the
bits to public flags upfront.

We define the following public flags:

| Value | Name | Description |
| -- | -- | -- |
| 1 << 0 | #nxdomain | DNS query failed with NXDOMAIN |
| 1 << 1 | #dnsTimeout | DNS query timed out |
| 1 << 2 | #bogon | DNS served replied with one or more bogon addresses |
| 1 << 3 | #dnsNoAnswer | DNS query succeded but there are no answers |
| 1 << 4 | #dnsRefused | DNS query failed with Refused |
| 1 << 5 | #dnsDiff | We think two set of DNS addresses are not compatible |
| 1 << 6 | #dnsServFail | DNS query failed with ServFail |
| 1 << 7 | #tcpTimeout | TCP connect attempt timed out |
| 1 << 8 | #tcpRefused | TCP connect attempt failed with ECONNREFUSED |
| 1 << 9 | #quicTimeout | QUIC timeout during or after handshake |
| 1 << 10 | #tlsTimeout | TLS timeout during or after handshake |
| 1 << 11 | #tlsEOF | Unexpected EOF during or after the handshake |
| 1 << 12 | #tlsReset | ECONNRESET during or after the handshake |
| 1 << 13 | #certificate | Cannot verify or validate TLS/QUIC certificate |
| 1 << 14 | #httpDiff | We believe two HTTP replies are different |
| 1 << 15 | #httpTimeout | Timeout during or after the HTTP round trip |
| 1 << 16 | #httpReset | Timeout during or after the HTTP round trip |
| 1 << 17 | #httpEOF | Unexpected EOF during or after the HTTP round trip |

We define the following private flags (note that there is no specific value
for them because their values may change over time):

| Name | Description |
| -- | -- |
| #inconclusive | We cannot reach a final conclusion |
| #probeBug | The measurement triggered some bug in the client |
| #httpDiffStatusCode | HTTP status code is different |
| #httpDiffTitle | HTTP title is different |
| #httpDiffHeaders | Uncommon HTTP headers are different |
| #httpDiffBodyLength | The body length is more different than reasonable |
| #httpDiffLegitimateRedirect | There's a diff but still we see a legitimate redirect |
| #httpDiffTransparentProxy | The client or the TH is behind an HTTP transparent proxy |

Note that `#httpDiffLegitimateRedirect` and `#httpDiffTransparentProxy` are
detected and avoided false-positive cases. There may be enough differences to
warrant an `#httpDiff`, but saying that would be a false positive because we
can instead explain those differences with a legitimate redirect
or a transparent proxy. (More on these false-positives
conditions later.)


### 4.2.3. DNS measurements analysis

This algorithm inspects each DNS measurement performed by the client. For each
inspected DNS measurement, it returns an AnalysisDetails structure.

The high-level objective of this algorithm is to:

1. determine that we cannot trust this DNS lookup because it includes bogons, or

2. determine that we can trust this DNS lookup because we can use some of its
IP addresses to establish authenticated TLS/QUIC sessions, or

3. find a matching lookup performed by the TH and determine whether the returned
error or set of IP addresses looks reasonable when compared to TH results.

The following Python pseudo-code describes the algorithm.

We create an `AnalysisDetails` data structure with its own unique `id` (unique
within the `Testkeys`) that refers to the DNS measurement's `id` in its
`refs` field.

```Python
def analyze_single_dns_lookup(lookup: DNSLookupMeasurement) -> AnalysisDetails:
    out = AnalysisDetails()
    out.id = new_unique_id()
    out.refs.append(lookup.id)
```

If the DNS lookup did not fail at the network or DNS level and any answer includes a bogon IP address, we raise the `#bogon` flag. We then return the
`AnalysisDetails` data structure to the caller.

```Python
    if lookup.Failure == "":
        if lookup.contains_bogons():
            out.flags |= analysis_flag_bogon
            return out
```

If we could use any of the IP addresses returned by this lookup 
to establish a TLS/QUIC session by the client or the TH, then we say that the
resolver is not lying to us and return the `AnalysisDetails` structure to
the caller.

```Python
        if any_address_worked_with_https(lookup):
            return out
```

We search for a matching DNS lookup measurement performed by the TH using the
same equality rule previously defined for the TH cache. If we cannot find
a matching measurement, this is a `#probeBug` because a matching TH
measurement should always exist. Then, we return the `AnalysisDetails` structure to the caller.

```Python
    matching = find_matching_dns_lookup(lookup)
    if matching is None:
        out.flags |= analysis_probe_bug
        return out
```

We add the matching TH measurement to the `refs` field of the
`AnalysisDetails` data structure and continue processing.

```Python
    out.refs.append(matching.id)
```

If both the client's and the TH measurement failed with the same
error, this is a consistent failure, so there is nothing else to do, and we return the `AnalysisDetails` structure.

```Python
    if lookup.failure != "" and matching.failure != "":
        if lookup.failure == matching.failure:
            return
```

If the failures are inconsistent, instead, we raise the `#inconclusive`
flag and return the `AnalysisDetails` structure to the caller.

```Python
        out.flags |= analysis_flag_inconclusive
        return out
```

If just the TH measurement failed, we also raise `#inconclusive` and return the `AnalysisDetails` structure.

```Python
    if matching.failure != "":
        out.flags |= analysis_flag_inconclusive
        return out
```

Then we map all the failures. If the failure is not among
the ones we intercept, declare the measurement as `#inconclusive`. We may
need to monitor `#inconclusive` measurements to figure out
whether there are other ways of blocking the DNS.

```Python
    if lookup.failure != "":
        if lookup.failure == NXDOMAIN:
            out.flags |= analysis_flag_nxdomain
        elif lookup.failure == REFUSED:
            out.flags |= analysis_flag_dns_refused
        elif lookup.failure == TIMEOUT:
            out.flags |= analysis_flag_dns_timeout
        elif lookup.failure == DNS_NO_ANSWER:
            out.flags |= analysis_flag_dns_no_answer
        elif lookup.failure == DNS_SERVFAIL:
            out.flags |= analysis_flag_dns_servfail
        else:
            out.flags |= analysis_flag_inconclusive
        return out
```

Otherwise, we may have a case of `#dnsDiff`. To determine that we
run the `analysis_dns_diff` algorithm.

```Python
    out.flags |= analysis_dns_diff(lookup, matching)
    return out
```

Such an algorithm is derived
from Web Connectivity and works as follows:

1. There is no diff if the intersection of the IP addresses resolved by `lookup` and `matching` is not empty.

2. There is no diff if the intersection of the public suffixes of the
reverse lookups of the IP addresses resolved by `lookup` and the ones resolved by `matching` is not empty. (The TH will perform a PTR lookup for each resolved IP
address and provide this information to the client.)

3. There is no diff if the intersection of the ASNs of the IP addresses
resolved by `lookup` and `matching` is not empty. (Either the TH will
annotate the resolved IP addresses, or the client needs to include a
GeoIP database for mapping IPs to ASNs.)

4. Otherwise, there is `#dnsDiff`.

This algorithm for determining whether there is a `#dnsDiff` may
cause false positives (for domains hosted by multiple CDNs) and
negatives (for blockpages hosted on the same CDN as the blocked
website). We always attempt to establish HTTPS sessions, even for
HTTP URLs, because the HTTPS oracle is quite powerful to determine
whether a set of IP addresses is legitimate.

### 4.2.4. Endpoint measurements analysis

This algorithm inspects each endpoint measurement performed by the client. For each
inspected measurement, it returns an AnalysisDetails structure.

The high-level objective of this algorithm is to:

1. determine that we cannot trust this measurement because it includes bogons, or

2. determine that we can trust this measurement because it can establish authenticated TLS/QUIC sessions, or

3. find a matching measurement performed by the TH and determine whether the returned
error or webpage looks reasonable when compared to TH results.

The following Python pseudo-code describes the algorithm.

We create an `AnalysisDetails` data structure with its own unique `id` (unique
within the `Testkeys`) that refers to the endpoint measurement's `id` in its
`refs` field.

```Python
def analyze_single_endpoint(epnt: EndpointMeasurement) -> AnalysisDetails:
    out = AnalysisDetails()
    out.id = new_unique_id()
    out.refs.append(epnt.id)
```

If the DNS measurement uses a bogon IP address, we raise the
`#bogon` flag. We then return the
`AnalysisDetails` data structure to the caller.

```Python
    if is_bogon(epnt.ip_address()):
        out.flags |= analysis_flag_bogon
        return out
```

If there is no failure and the scheme is HTTPS, then we say that
this measurement is good (thereby fully trusting the CA we bundle).

```Python
    if epnt.failure == "" and epnt.scheme() == "https":
        return out
```

Now we search for a matching TH measurement. If we cannot find
one, it is a `#probeBug` because there should be one. For matching, we use the same rules defined for the TH cache.

```Python
    matching = find_matching_endpoint_measurement(epnt)
    if not matching:
        out.flags |= analysis_probe_bug
        return out
```

At this point, we append the matching measurement ID to the `refs`.

```Python
    out.refs.append(matching.id)
```

Then, we check for consistent and inconsistent failures, and we
handle them as we did for DNS measurements:

```Python
    if epnt.failure != "" and matching.failure != "":
        if epnt.failure == matching.failure:
            return out
        out.flags |= analysis_inconclusive
        return out
```

As for the DNS, we treat a TH failure as `#inconclusive`:

```Python
    if matching.failure != "":
        out.flags |= analysis_flag_inconclusive
        return out
```

Now we try to analyze the case in which just `epnt` failed. We
start with checking for TCP connect errors. As we did before,
we flag as `#inconclusive` any error we do not explicitly
handle. (This specific choice means that we are going
to give less relevance in Explorer to measurements that
fail in a way that is unforeseen by us.)

```Python
    if epnt.failure != "":
        if epnt.failed_operation == "tcp_connect":
            if epnt.failure == TIMEOUT:
                out.flags |= analysis_flag_tcp_timeout
                return out
            if epnt.failure == ECONNREFUSED:
                out.flags |= analysis_flag_tcp_refused
                return out
            out.flags |= analysis_flag_inconclusive
            return out
```

We continue by checking for TLS handshake errors:

```Python
        if epnt.failed_operation == "tls_handshake":
            if epnt.failure == TIMEOUT:
                out.flags |= analysis_flag_tls_timeout
                return out
            if epnt.failure == ECONNRESET:
                out.flags |= analysis_flag_tls_reset
                return out
            if epnt.failure in CERTIFICATE_ERRORS:
                out.flags |= analysis_flag_certificate
                return out
            if epnt.failure == EOF:
                out.flags |= analysis_flag_tls_eof
                return out
            out.flags |= analysis_flag_inconclusive
            return out
```

Next, we deal with QUIC handshake errors:

```Python
        if epnt.failed_operation == "quic_handshake":
            if epnt.failure == TIMEOUT:
                out.flags |= analysis_flag_quic_timeout
                return out
            if epnt.failure in CERTIFICATE_ERRORS:
                out.flags |= analysis_flag_certificate
                return out
            out.flags |= analysis_flag_inconclusive
            return out
```

The final failure mode deals with the HTTP round trip. Here we try to
attribute the failure to the highest-level adversary observable
network protocol (i.e., TLS for HTTPS, QUIC for HTTP3, and HTTP for
HTTP). We return `#probeBug` or `#inclusive` where applicable.

```Python
        if epnt.failed_operation == "http_round_trip":

            if epnt.failure == TIMEOUT:
                if epnt.is_http():
                    out.flags |= analysis_flag_http_timeout
                    return out
                if epnt.is_https() and epnt.network == "quic":
                    out.flags |= analysis_flag_quic_timeout
                    return out
                if epnt.is_https() and epnt.network == "tcp":
                    out.flags |= analysis_flag_tls_timeout
                    return out
                out.flags |= analysis_flag_probe_bug
                return out

            if epnt.failure == ECONNRESET:
                if epnt.is_http():
                    out.flags |= analysis_flag_http_reset
                    return out
                if epnt.is_https() and epnt.network == "tcp":
                    out.flags |= analysis_flag_tls_reset
                    return out
                out.flags |= analysis_flag_probe_bug
                return out

            if epnt.failure == EOF:
                if epnt.is_http():
                    out.flags |= analysis_flag_http_eof
                    return out
                if epnt.is_https() and epnt.network == "tcp":
                    out.flags |= analysis_flag_tls_eof
                    return out
                out.flags |= analysis_flag_probe_bug
                return out

            if epnt.is_http() or epnt.is_https():
                out.flags |= analysis_flag_inconclusive
                return out

            out.flags |= analysis_flag_probe_bug
            return out
```

If everything else fails, we apply an `#httpDiff` algorithm
derived from Web Connectivity. See also how we handle some
false positives in case of `#httpDiff` (more details later):

```Python
    web_flags = analysis_http_diff(epnt, matching)
    if (web_flags & (analysis_http_diff|analysis_http_diff_status_code)) != 0:
        if is_transparent_proxy_redirect(epnt):
            out.flags |= analysis_http_diff_transparent_proxy
            return out
        if seems_legitimate_redirect(epnt, matching):
            out.flags |= analysis_http_diff_legitimate_redirect
            return out
        if seems_legitimate_redirect(matching, epnt):
            out.flags |= analysis_http_diff_legitimate_redirect
            return out
```

If none of these checks for false positives apply, we return the result
of the `#httpDiff` algorithm to the caller:

```Python
    out.flags |= web_flags
    return out
```

In the following subsections, we describe the `#httpDiff`, 
transparent-proxy and legitimate-redirect algorithms.

##### 4.2.4.1. The #httpDiff algorithm

This algorithm derives from Web Connectivity. We perform four
checks before determining whether there is `#httpDiff`:

1. We set `#httpDiffStatusCode` if the status codes are
different, and the `matching` endpoint's status code is either `200` or a redirect. We instead set `#inconclusive`
if the `matching` endpoint status code is 4xx or 5xx.

2. We set `#httpDiffBodyLength` if the body length is not
truncated for both `epnt` and `matching`, and the ratio
of the smaller body over the larger one is less than 70%.

3. We set `#httpDiffHeaders` if there is no intersection
of the uncommon HTTP headers between `epnt` and `matching` using the list of uncommon headers that probe-cli's
Web Connectivity uses as of v3.14.1.

4. We set `#httpDiffTitle` if there are no longer-than-5
chars common words between the titles of the `epnt` and `matching` web pages. 

**EDITOR'S NOTE**: before approving this spec, we should
review the effectiveness of these heuristics in light of
the data we have collected since we implemented the Web
Connectivity algorithm. It may be that some of them
could be improved (e.g., the `#httpDiffHeaders` one by
reviewing what blockpages look like in general).

Once we have evaluated these four conditions, we combine
them to decide whether there is an `#httpDiff`:

1. if `#httpDiffStatusCode` is set we set `#httpDiff`
and return to the caller;

2. if `#httpDiffBodyLength` is not set, we say there is
no `#httpDiff` and return to the caller;

3. if `#httpDiffHeaders` is not set, likewise;

4. if `#httpDiffTitle` is not set, likewise;

5. otherwise, we set the `#httpDiff` flag and return.

We also do not set `#httpDiff` in case of `#probeBug` in
any of the `#httpDiff` sub-algorithms.

##### 4.2.4.2. Transparent proxies

We have seen several cases where the TH gets
redirected from HTTP to HTTPS to fetch a given
webpage, while the client obtains the same webpage
from its HTTP request. We suspect this class of
false positives may be related to transparent HTTP
proxies. Of course, the `#httpDiff` algorithm
flags this condition because the status code is
different, and the body is also different.

However, we always test HTTPS along with HTTP. Thus,
we can compare the webpage returned
by `epnt` with the corresponding TH measurement
using HTTPS instead of HTTP. We run again the
`#httpDiff` algorithm on those two measurements, and we
return whether they match. As we have seen before,
when this happens, the caller will
set `#httpDiffTransparentProxy`.

##### 4.2.4.3. Legitimate redirects

We have seen cases where a server redirects a
client to a language-specific domain. For example, in
China, bing.com redirects to cn.bing.com.
This condition causes `#httpDiff` in several
cases, most often when the TH _is not_
redirected as well. To avoid flagging this
class of issues as false positives, we
check whether the redirect target has the
same public suffix or the domain in the URL
we are testing. If that is the case, we
consider this redirect legitimate and avoid
flagging the endpoint as `#httpDiff`, setting
the `#httpDiffLegitimateRedirect` flag instead.

#### 4.3. Cross-comparing TH measurements

This analysis algorithm splits TH measurements into
two sets. The set with IP addresses discovered by the client
only and the one with IP addresses discovered by the
TH only. (We exclude, indirectly, bogons because the TH
does not attempt to measure this class of IP addresses.)

If some or all DNS resolutions performed by the
probe return invalid addresses for the domain, we
expect to see one of the following conditions:

1. all the TH measurements using probe addresses
fail, whole the other measurements succeed. We see this
case, for example, in China, where several
DNS lookups for blocked domains return random IP
addresses.

2. all the TH measurements using probe addresses
return significantly different replies than
the other measurements. We see this case, for example,
in Italy, where local resolvers return
the IP addresses of blockpages for blocked
domains.

**EDITOR'S NOTE**: we are still researching on
how exactly to represent this analysis into the
results.

### 4.4. Aggregating results

Once we have computed flags for each DNS and
endpoint, we aggregate flags for the whole
`SingleStepMeasurement` by computing the bitwise
OR of all the computed flags. We also remove
from the final result all the analyses that
did not produce any flags.

Lastly, we compute the aggregate flags for the
whole `TestKeys` by computing the bitwise OR
or all the `SingleStepMeasurement` flags.

## 5. Privacy considerations

As for Web Connectivity, websteps measurements may
accidentally include PII. Implementations MUST discover
the user's IP address and ensure to replace it with a
string such as `[redacted]` (like OONI Probe does)
before submitting the measurement JSON.

## 6. Copyright and license

Copyright 2022 Open Observatory of Network Interference.

SPDX-License-Identifier: BSD-3-Clause.
