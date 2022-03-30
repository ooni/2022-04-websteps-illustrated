"""
Exports all the types in the OONI archival data format.
"""

from .pkg_archival import (
    ArchivalBinaryData,
    ArchivalDNSAnswer,
    ArchivalDNSLookupResult,
    ArchivalNetworkEvent,
    ArchivalTCPConnectStatus,
    ArchivalTCPConnectResult,
    ArchivalTLSOrQUICHandshakeResult,
    ArchivalMaybeBinaryData,
    ArchivalHTTPTor,
    ArchivalHTTPRequest,
    ArchivalHTTPResponse,
    ArchivalHTTPRequestResult,
)

BinaryData = ArchivalBinaryData
DNSAnswer = ArchivalDNSAnswer
DNSLookupResult = ArchivalDNSLookupResult
NetworkEvent = ArchivalNetworkEvent
TCPConnectStatus = ArchivalTCPConnectStatus
TCPConnectResult = ArchivalTCPConnectResult
TLSOrQUICHandshakeResult = ArchivalTLSOrQUICHandshakeResult
MaybeBinaryData = ArchivalMaybeBinaryData
HTTPTor = ArchivalHTTPTor
HTTPRequest = ArchivalHTTPRequest
HTTPResponse = ArchivalHTTPResponse
HTTPRequestResult = ArchivalHTTPRequestResult

from .pkg_dnsping import (
    DNSPingArchivalSinglePingReply,
    DNSPingArchivalSinglePingResult,
    DNSPingArchivalResult,
)

DNSPingSinglePingReply = DNSPingArchivalSinglePingReply
DNSPingSinglePingResult = DNSPingArchivalSinglePingResult
DNSPingResult = DNSPingArchivalResult

from .pkg_measurex import (
    MeasurexArchivalURLMeasurement,
    MeasurexArchivalDNSLookupMeasurement,
    MeasurexArchivalEndpointMeasurement,
)

MeasurexURLMeasurement = MeasurexArchivalURLMeasurement
MeasurexDNSLookupMeasurement = MeasurexArchivalDNSLookupMeasurement
MeasurexEndpointMeasurement = MeasurexArchivalEndpointMeasurement

from .pkg_websteps import (
    WebstepsArchivalTestKeys,
    WebstepsArchivalSingleStepMeasurement,
    WebstepsArchivalTHResponse,
    WebstepsAnalysis,
    WebstepsAnalysisDNSOrEndpoint,
    WebstepsAnalysisFlagsWrapper,
)

WebstepsTestKeys = WebstepsArchivalTestKeys
WebstepsSingleStepMeasurement = WebstepsArchivalSingleStepMeasurement
WebstepsTHResponse = WebstepsArchivalTHResponse
WebstepsAnalysis = WebstepsAnalysis
WebstepsAnalysisDNSOrEndpoint = WebstepsAnalysisDNSOrEndpoint
WebstepsAnalysisFlagsWrapper = WebstepsAnalysisFlagsWrapper
