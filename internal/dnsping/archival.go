package dnsping

//
// Archival
//
// Converting results to the archival format.
//

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/miekg/dns"
)

// ArchivalSinglePingReply is the archival format of SinglePingReply.
type ArchivalSinglePingReply struct {
	Addresses     []string                  `json:"addresses"`
	ALPNs         []string                  `json:"alpns"`
	Failure       *string                   `json:"failure"`
	ID            int64                     `json:"id"`
	Reply         *model.ArchivalBinaryData `json:"reply"`
	SourceAddress string                    `json:"source_address"`
	T             float64                   `json:"t"`
}

// ToArchival returns the archival representation
func (spr *SinglePingReply) ToArchival(begin time.Time) *ArchivalSinglePingReply {
	return &ArchivalSinglePingReply{
		Addresses:     spr.Addresses,
		ALPNs:         spr.ALPNs,
		Failure:       spr.Error.ToArchivalFailure(),
		ID:            spr.ID,
		Reply:         model.NewArchivalBinaryData(spr.Reply),
		SourceAddress: spr.SourceAddress,
		T:             spr.Finished.Sub(begin).Seconds(),
	}
}

// ArchivalSinglePingResult is the archival format of SinglePingResult.
type ArchivalSinglePingResult struct {
	Hostname        string                     `json:"hostname"`
	ID              int64                      `json:"id"`
	Query           *model.ArchivalBinaryData  `json:"query"`
	ResolverAddress string                     `json:"resolver_address"`
	QueryType       string                     `json:"query_type"`
	T               float64                    `json:"t"`
	Replies         []*ArchivalSinglePingReply `json:"replies"`
}

// ToArchival returns the archival representation
func (spr *SinglePingResult) ToArchival(begin time.Time) *ArchivalSinglePingResult {
	out := &ArchivalSinglePingResult{
		Hostname:        spr.Domain,
		ID:              spr.ID,
		Query:           model.NewArchivalBinaryData(spr.Query),
		ResolverAddress: spr.ResolverAddress,
		QueryType:       dns.TypeToString[spr.QueryType],
		T:               spr.Started.Sub(begin).Seconds(),
		Replies:         []*ArchivalSinglePingReply{},
	}
	for _, entry := range spr.Replies {
		out.Replies = append(out.Replies, entry.ToArchival(begin))
	}
	return out
}

// ArchivalResult is the archival format of Result
type ArchivalResult struct {
	Pings []*ArchivalSinglePingResult `json:"pings"`
}

// ToArchival returns the archival representation
func (ar *Result) ToArchival(begin time.Time) *ArchivalResult {
	out := &ArchivalResult{}
	for _, entry := range ar.Pings {
		out.Pings = append(out.Pings, entry.ToArchival(begin))
	}
	return out
}
