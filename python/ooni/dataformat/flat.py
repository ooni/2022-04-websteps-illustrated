"""
Exports all the types in the "flat" data format.
"""

from .pkg_archival import (
    FlatDNSLookupEvent,
    FlatDNSRoundTripEvent,
    FlatHTTPHeader,
    FlatHTTPRoundTripEvent,
    FlatNetworkEvent,
    FlatQUICTLSHandshake,
)

DNSLookupEvent = FlatDNSLookupEvent
DNSRoundTripEvent = FlatDNSRoundTripEvent
HTTPHeader = FlatHTTPHeader
HTTPRoundTripEvent = FlatHTTPRoundTripEvent
NetworkEvent = FlatNetworkEvent
QUICTLSHandshake = FlatQUICTLSHandshake

from .pkg_measurex import (
    MeasurexSimpleURL,
    MeasurexCookie,
    MeasurexDNSLookupMeasurement,
    MeasurexEndpointMeasurement,
)

MeasurexSimpleURL = MeasurexSimpleURL
MeasurexCookie = MeasurexCookie
MeasurexDNSLookupMeasurement = MeasurexDNSLookupMeasurement
MeasurexEndpointMeasurement = MeasurexEndpointMeasurement
