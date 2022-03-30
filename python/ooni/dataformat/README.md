# Python library for parsing OONI data formats

This library provides support for parsing the two data formats
that websteps generates:

1. the "flat" data format used in caches;

2. the "archival" data format used for OONI measurements.

For each struct type inside the Go implementation, there is a
Python class that holds the same information.
