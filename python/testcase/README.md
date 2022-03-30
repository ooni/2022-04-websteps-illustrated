# testcase

This directory contains code to manage websteps testcases.

* `./python/testcase/create` is a minimal wrapper around `./cmd/websteps`
allowing you to collect information required to produce a testcase

* `./python/testcase/shell` is a shell for managing test cases

A websteps testcase is a YAML file containing metadata and websteps
cache information required to execute again the same measurement.

To this end, we execute `./cmd/websteps` and `./cmd/thd` in a mode that
forbids using the network and only reads input from the cache.

We can thus perform a local measurement under the same censorship
conditions of the original measurement.

The results returned from the cache are constants and predictable, which
allows us to continue testing and improving websteps algorithms.
