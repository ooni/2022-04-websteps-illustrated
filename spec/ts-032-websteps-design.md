# Websteps: measuring HTTP/HTTPS/HTTP3 blocking

Websteps is a redesign of OONI's webconnectivity experiment. This
document only contains the design rationale and updates since previous
designs. Separate documents describe other websteps related topics.

| | |
| -- | -- |
| Version | 2022.04.04 |
| Author | Simone Basso |
| Status | Draft |


## Summary of changes since last revision and highlights

1. added heuristics to reduce the exploration space (i.e., we
are not testing all the endpoints anymore);

2. now we test `1<<19` bytes because of blockpages and throttling;

3. complete specification of the analysis algorithm and
implementation of such an algorithm inside the probe;

4. one month of experience with running this codebase in
several countries (China, Italy, Iran);

5. we still need at least 1 Mbit/s now in the common
configuration but we also have custom options that allow
for running websteps in low-bandwidth scenarios;

6. now we emit a single measurement including all the
redirections and the data format assigns a unique ID to
every relevant piece of measurement, therefore it's
much easier to connect each sub-measurement to other
sub-measurements and perform data analysis (it's
actually quite easy to unpack a websteps measurement
into a set of tabular observations);

7. Python library for loading/parsing websteps measurements
and reference (toy) client in Python to have more confidence
that the spec could be implemented in other languages and
different implementations may interoperate;

8. we are now checking for duplicate DNS answers using
the `websteps-dnsping` extension;

9. we now guess the intent of the test list URL and
choose the right number of bytes to download accordingly (this
is one of the many changes to save bandwidth and avoid
useless measurements);

10. now we have a cache in the TH and the caching
mecanism is also super useful for integration testing;

11. the conceptual work to improve the vocabulary
and concepts with which we describe measurements has
made reasoning about websteps absolutely much simpler (i.e.,
redirects and cookies do not seem conceptually problematic
to handle anymore);

12. measuring and submitting HTTP and HTTPS together
allows to reinforce the strength of the analysis
by cross using measurements to make higher-quality
statements about what is happening;

13. limiting the number of endpoints we test helps
not only with the measurement runtime but also to
avoid triggering rate-limiting server side (eh... who would have guessed...);

14. websteps probably need some form of compression, which
is either brutal gzip/zstd/lzma or some more advanced
form of understanding that bodies are ~same and we don't
need to submit multiple copies;

15. we now have a greedy mode (on by default), where we
do not continue following redirects if we find enough
anomalies (several URLs in the test list are either fully
blocked or parked domains that are accessible once you
overcome the initial DNS-based-blocking).

## Comparison with Web Connectivity

We still aim to mainly address Web Connectivity limitations
without completely twisting the original model. The following table
provides a honest side-by-side comparison of websteps and Web Connectivity features.

| Feature  | Web Connectivity | Websteps |
| -- | -- | -- |
| using IP addresses from the control  | no | yes |
| explicit DNS-over-UDP measurements   | no | yes |
| testing all available addresses      | partial | configurable |
| support for QUIC/HTTP3 measurements  | no | yes |
| bogons cause confirmed anomalies     | no | yes |
| explicit view of redirects           | no | yes |
| support for measuring throttling     | partial | full |
| support for collecting blockpages    | yes | yes |
| separates observation and analysis   | no | yes |
| optimized for low bandwidth          | no | configurable |
| data model complexity                | nested | flat/ID-addressable |
| extensible model w/ follow-ups       | harder | easier/built-in |
| discovers multiple blocking reasons  | no | yes |
| generated JSONs size                 | large (bodies!) | larger |
| ready for a richer check-in API      | no | yes |
| HTTPS oracle to validate DNS lookups | no | yes |
| TH oracle to validate DNS lookups    | no | yes |
| detailed log explaining analysis     | partial | full |
| supports emoji-rich output           | no | yes |
| initially measures HTTP and HTTPS    | no | yes |
| has run in production for years      | yes | no |
| includes Python data loading library | yes | yes |
| Fully typed data model               | partial | yes |
| integration testing strategy(*)      | jafar | mxcache |
| TH supports websockets               | no | yes |
| tries to avoid DNS and HTTP diff     | no | yes |
| risk of #dnsDiff false positives     | higher(?) | low |
| risk of #httpDiff false negatives    | low | higher(?) |
| honours cookies for redirects        | yes | yes |
| tries to avoid unnecessary redirects | no | yes |

Some clarifications are in order. When I say "tries to avoid
DNS and HTTP diff" I mean that websteps analysis tries its
best to cross reference with other data sources to avoid
performing a classical Web Connectivity style DNS diff or
HTTP diff comparison. For example: bogons, information
from the test helper about how different IP addresses resolved
by the probe or the TH behave. Of course, Web Connectivity
does lots of HTTP/DNS diff
because it is a core tenet of its design.

Regarding the integration testing strategy:

- `jafar` is a tool that emulates censorship locally on Linux
systems using netfilter and we have `jafar2` designs that also
include network namespaces and `netem` emulation;

- `mxcache` is a cache framework in websteps that allows to
collect TH and probe measurements and run, in the future, new
websteps measurements that use the cache rather than the
network, thus allowing re-running integration tests based
on low-level data points collected in censored environments.

I think, in going forward, we should use `netem` to emulate
bad networking conditions and we should try to privilege
integration testing based on real-world censorship data as
opposed to generating synthetic censorship.

Regarding `#httpDiff` false negatives, the discussion is
actually subtle and depend a lot on the definition we give
to `#httpDiff`. Websteps tends to say that there is a DNS
diff when the DNS resolver lies. We seem empirically to
have more confidence on Web Connectivity's `#httpDiff` than
on `#dnsDiff`. This occurs because:

1. Websteps includes more DNS data points and compares
measurements using IPs resolved by the probe with measurements
using IPs resolved by the TH, therefore there are more data
points useful to determine there's a `#dnsDiff`;

2. Websteps sees many more pages for measurement while
Web Connectivity only has to compare a single page from
the probe with the system resolver's IP address with
another one from the TH with a non-censored resolver, which
means that websteps' task is more complex and it may see
many more nuances (like legitimate IP addresses of the same
domain that return different webpages,
transparent HTTP proxies in the middle, etc.).

In conclusion, websteps seems much more likely to attribute
issues to the DNS when the DNS is lying, while Web
Connectivity has less DNS data points but an easier A/B
webpages comparison task and could potentially say
that there's `#httpDiff` more frequently. So, the current
design of Web Connectivity may be more robust in case
there's transparent HTTP proxy based censorship without
any kind of DNS interference.

(OTOH, when the root cause of censorship is the DNS it may
not be that inaccurate to say `#dnsDiff`. Still, the
fringe of improving websteps is to be able to say also
`#httpDiff`, even though probably the original heuristics
developed for Web Connectivity need an upgrade because
websteps operates a bit differently.)

There is no comparison in terms of reporting multiple cases
of blocking (i.e., bogons or random IP addresses coupled
with TLS or QUIC blocking). Websteps will identify all the
reasons for blocking; Web Connectivity will always conclude
`#dns` or `#dnsDiff` because it is designed to classify to
a single censorship condition.

## Work that still remains to be done

Improvements in detecting `#httpDiff`, possibly by continuing
to invest in using TH data for comparing IPs resolved by the
probe to IPs resolved by the TH.

We need to re-run analysis in bad networking conditions and
ensure websteps does not exaggerate with parallelism.

We most likely need to implement compression to significantly
reduce the size of the submitted measurements. (This improvement
would acutally also be beneficial to Web Connectivity.)

We need to design a continuous data quality monitoring process
for websteps, that possibly also helps to maintain the test list
in the process (e.g., by pruning URLs, updating URLs, flagging
some URLs as parked domains).

## FAQ

This section contains a bunch of questions related to the design
we've been dragging along for quite some time. Here I'm trying to
update the answers and explain what changed since the last month
of focused work on websteps.

1. How to fix websteps to test all endpoints?

We have configuration. The strategy for a `websteps --deep`
scan is to allow websteps to wait/sleep between endpoint
measurements to avoid overloading the destination servers.

This mode should not be the default mode but could still
be quite useful when performing censorship research.

2. Why did we stopped issuing HTTPSSvc queries?

Because they are seldomly supported and censors reply
to them like they were A/AAAA anyway.

3. Why do we follow redirects?

We need to follow _some_ redirects when this matters for
throttling. We have however spent time to avoid following
useless redirects and we could probably do a bit more in
this spage (e.g., avoid following an HTTPS redirect to the
same domain caused by a URL with `/` in its path).

4. Why do we download so many bytes of the response body?

Throttling and blockpages. However, websteps is now configurable
and in the future we can tweak the behavior using the check-in
API on an URL, country, and ASN basis. So we can further reduce
the amount of unnecessary work. Already now, a user can run
websteps telling it to not download any body of any request, which
makes websteps a good scanner for pure TCP/TLS/QUIC handshake
blocking.

5. Why do we use both the system and a UDP resolver?

To pitch them one against the other in data analysis and discover
the extent of DNS blocking in a country/ASN.

6. Why is the analysis algorithm not so simple anymore?

To understand websteps' potentialities we needed to implement
a full analysis algorithm somewhere. Also, some decisions that
websteps need to take cannot be taken ~easily without analysis.

(See also the next question and answer.)

7. Why not performing SNI-blocking follow-up measurements?

We're actually getting there. Now we already have a `dnsping`
follow up, which is great to improve our DNS analysis.

BTW, an "autonomous nervous system for OONI" requires (and if not
requires at least benefits a lot) to have analysis in the probe
to take decisions.

8. Why not checking for duplicate DNS answers?

Actually, now we do using `dnsping`.

9. Why not checking for DNS injection using root servers?

Eh, we actually need to write more code to do that. It feels
however another nice exteension to implement.

11. Why do websteps on paper seem so slow and seem to consume so much bandwidth?

I agree this seems the case on paper, but we should also
run real performance measurements (e.g., phone in 2G or 3G mode,
netem) and repeat [probe#1797](https://github.com/ooni/probe/issues/1797).

12. Why are websteps measurements so large?

Currently, they are large because we submit several copies of
the same body, one for each endpoint. We should figure out a way
to avoid submitting several copies of the same body, or we
should perhaps just compress measurements?

13. Why do websteps not try to guess the intent of a test list URL?

We actually do that now. This heuristic will eventually become
obsolete with a richer check-in API, but I'd like to time-to-market a
good-enough strategy immediately.

14. Why is websteps so complex? Can’t we serve smarter input to the probes?

With better conceptual understanding and organization of the codebase,
complexity now feels much lower than a month ago (go figure...).

15. Why don’t you distinguish between random and hard anomalies?

We are trying to tackle random anomalies with follow up measurements. For
example `dnsping` is there to confirm DNS timeouts or show that they actually
were just transient phenomena. Likewise, `dnsping` is there to collect more
data (e.g., duplicate or triple replies) in case of hard failures, e.g.,
`NXDOMAIN` or bogon reply.

Other follow-up experiments should follow this model. Not run by default
but triggered to gather further evidence when we need it.

16. Why does this new iteration include throttling?

It seems throttling is happening, therefore it makes sense to at least have
some rough way of detecting it. We have seen that we can spot heavy signs
of throttling with Web Connectivity. This calls for using equally large bodies at least.

17. Why does this new iteration not focus on TLS fingerprinting?

One thing at a time, we'll eventually get to uTLS like measurements.

18. Why does this new iteration not focus on stateful endpoint blocking?

I kept this question from the original FAQ but I think I may have
misunderstood the original problem. So, I think the original answer
is not good anymore :-).

19. Why don’t we characterize precisely all conditions we would like to flag?

We actually do that now. We needed to start implementing
this somewhere to understand the websteps mode and we
did this in the probe.

20. Why does this iteration run the test helper in
parallel with other measurements?

Because this speeds up measurements when there is no interference. (It’s also more code complexity but it seems worth having and, again, after one month
of code and conceptual policing, it does not seem so complex or patchy anymore.)

22. Why does websteps truncate the body? We need it to detect blockpages!

Yeah, point taken. I actually bumped cleartext HTTP
bodies back to `1 << 19` bytes.

23. Why does this proposal not mention honoring cookies?

So, since the last iteration we actually figured out cookie handling :-).

24. Why not run two distinct flows for HTTP and HTTPS? It seems
they have different measurement needs!

So, for example, it seems that running the websteps flow for cleartext
HTTP helps to discover transparent proxies, which is nice to know.

25. Why does the proposal advocate for submitting HTTPS
and HTTPS/HTTP3 together?

If we don't submit all the measurements
starting from an initial URL together, the pipline will have a hard
time to perform the same analysis of the probe.

26. Why don’t you limit the number of IP addresses/endpoints?

Point taken. Now we're limiting them. Also, it seems that on the field
not doing that is too slow and causes a bunch of rate limiting when
there are websites with dozens of addresses.
