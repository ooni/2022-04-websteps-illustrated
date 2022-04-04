# Websteps illustrated

This repository contains the third prototype of
[websteps](https://github.com/ooni/probe/issues/1714) (codename
"winter 2022"). This prototype follows after the
["summer 2021"](https://github.com/ooni/probe-cli/tree/v3.14.1/internal/engine/experiment/websteps)
and the
["fall 2021"](https://github.com/ooni/probe-cli/tree/v3.14.1/internal/engine/experiment/webstepsx)
protypes.

## Content of this repository

The [internal](internal) directory contains code derived from
[ooni/probe-cli](https://github.com/ooni/probe-cli/) v3.14.1 as
well as new code. As a rule of thumb, most directories could
be easily merged back, except `measurex` and `websteps`, which
have been significantly rewritten and would require either
more careful merging or a yolo-rewrite-everything approach.

The [cmd](cmd) directory contains commands using code in the
[internal](internal) library. The most important commands are:

- [cmd/websteps](cmd/websteps): websteps client;

- [cmd/thd](cmd/thd): test helper.

The [spec](spec) directory contains the current draft
specification of websteps, which still needs to be discussed
with my colleagues and other friends of OONI.

The [python](python) directory contains:

- [python/websteps.py](python/websteps.py): minimal implementation
of the websteps concept written in Python, not meant to become production ready,
but rather useful to see the algorithms in a smaller context
and show that websteps implementations not written in Go could
inter-operated with the test helper written in Go;

- [python/analysis/dbsteps](python/analysis/dbsteps): Python script
to analyze websteps measurements and view them in the browser;

- [python/testcase/create](python/testcase/create): script to create
integration test cases for websteps while running measurements;

- [python/testcase/shell](python/testcase/shell): script to manage
the integration tests for websteps;

- [python/ooni](python/ooni): comprehensive library to import
and process websteps measurements using Python.

The [testdata/testcase](testdata/testcase) directory contains a few
test cases collected using the [create](python/testcase/create)
command and managed using the [shell](python/testcase/shell) command.

The [html](html) directory contains support file for browsing
websteps measurements and test cases using HTML.

**NOTE**: while I spent some time to make this code polished, this is
still experimental code, with little unit testing and, for sure, a bunch
of inconsistencies betwenn the spec and the implementation. This is
normal, given that for now websteps is still a bit of a moving target.

## Building the websteps client

```bash
go build -v ./cmd/websteps
```

## Building the TH

```bash
go build -v ./cmd/thd
```

## Changes since websteps fall 2021

These are the main changes since the fall 2021 edition (collection?! 😅):

1. added support for `PTR` and `NS` queries as well as for
opportunistially extract the `CNAME` from replies;

2. implemented a parallel DNSResolver using custom DNSTransport;

3. reworked the system resolver to fake a DNSTransport and
produce more easily the OONI DNS data format;

4. several reliability and correctness fixes in DNS code;

5. significantly reworked the conceptual model of `measurex` to
more easily accommodate for implementing websteps;

6. around one month of experience running websteps code in
several countries (including China, Italy, and Iran), which
dramatically helped to improve the robustness of the
implementation as well as to develop "scoring" algorithms;

7. developed a set of algorithms to assign blocking flags
to websteps measurements as well as heuristics to spot common
classes of false positives and flag them correctly;

8. implemented and integrated a `dnsping` extension for
websteps that allows to confirm with more confidence cases
of DNS blocking as well as to retreat DNS timeout claims
when there are transient timeouts;

9. integration testing framework based on caching the
TH and the probe's measurements that is based on replaying
measurements collected on the field (thus being more
true to real world censorship than simulated censorship
using `jafar` or similar tools);

10. robust caching mechanism for the TH;

11. started experimenting with using `TLSH` to classify
webpages in addition to using the traditional Web Connectivity
algorithm (but this effort is so far a bit inconclusive).

This work addresses in part of completely:

| issue | level of completion |
| -- | -- |
| [probe#2034](https://github.com/ooni/probe/issues/2034) | complete |
| [probe#1190](https://github.com/ooni/probe/issues/1990) | complete |
| [probe#1806](https://github.com/ooni/probe/issues/1806) | complete |
| [probe#1803](https://github.com/ooni/probe/issues/1803) | now unnecessary |
| [probe#1516](https://github.com/ooni/probe/issues/1516) | mostly(?) complete |
| [probe#1718](https://github.com/ooni/probe/issues/1718) | complete |

## What happens now

- [ ] continuing to discuss the spec with OONI friends;

- [ ] prepare short presentation for pitching websteps since
the spec is long and it may be beneficial to also provide
people with short introductions;

- [ ] continue extensive data analysis and start preparing
reports/blog posts based on this work;

- [ ] write spec for extensions (including `dnsping`, already
implemented, and `sniblocking`, which we need);

- [ ] collect more test cases and add support for automatically
checking that we're still passing these test cases;

- [ ] figure out ways to auto-generate parts of the codebase
if possible (especially python data structs that depend on
Go data structs: that would be nice);

- [ ] perform again a performance comparison with Web Connectivity;

- [ ] double check that our level of parallelism is adequate
for testing in low bandwidth scenarios;

- [ ] start merging back into `probe-cli` the easy parts and
generally aim to reduce the diff between this fork and the
original codebase;

- [ ] sync up the OONI issue tracker with the work I have
beem doing here basically in `sti` mode.


## Nginx setup

If `thd` is running locally (and please rememeber to
force it to drop `root` privileges), you can integrate
it with an existing `nginx` setup by adding:

```
  location /websteps/v1/websocket {
      proxy_read_timeout 900;
      proxy_pass http://127.0.0.1:9876;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "Upgrade";
      proxy_set_header Host $host;
  }
  location /websteps/v1/http {
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_read_timeout 900;
      proxy_pass http://127.0.0.1:9876;
  }
```
