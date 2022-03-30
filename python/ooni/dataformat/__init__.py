"""
Manually curated library for processing JSONs emitted by ooniprobe.

This library understands two data formats:

1. the "flat" data format, used in the measurex cache;

2. the "archival" data format used to upload OONI measurements to
the OONI collector.

As such, this library is a suitable building block to manage
testcases as well as to process OONI measurements.

Submodules:

- `archival` contains all the definitions of the archival data
format: import this submodule if you need to parse OONI measurements;

- `flat` contains all the definitions of the "flat" data format:
import this submodule if you need to parse measurex's cache;

- `typecast` contains code for safely casting Any values obtained
from JSON parsing to the correct data types;

- we additionally have a module named after each package in the Go
implementation that deals with data format things (which makes
it significantly easier to understand what is the Go type corresponding to
a Python type defined by this library). These modules are named like
`pkg_foo` where `foo` is the corresponding Go package.
"""
