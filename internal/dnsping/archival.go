package dnsping

//
// Archival
//
// Converting results to the archival format.
//

import (
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// ArchivalSinglePingReply is the archival format of SinglePingReply.
type ArchivalSinglePingReply struct {
	Addresses     []string                  `json:"addresses"`
	ALPNs         []string                  `json:"alpns"`
	Failure       *string                   `json:"failure"`
	ID            int64                     `json:"id"`
	Rcode         string                    `json:"rcode"`
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
		Rcode:         spr.Rcode,
		Reply:         model.NewArchivalBinaryData(spr.Reply),
		SourceAddress: spr.SourceAddress,
		T:             spr.Finished.Sub(begin).Seconds(),
	}
}

// ArchivalSinglePingResult is the archival format of SinglePingResult.
type ArchivalSinglePingResult struct {
	Delay           float64                    `json:"delay"`
	Hostname        string                     `json:"hostname"`
	ID              int64                      `json:"id"`
	Query           *model.ArchivalBinaryData  `json:"query"`
	QueryID         int64                      `json:"query_id"`
	QueryType       string                     `json:"query_type"`
	ResolverAddress string                     `json:"resolver_address"`
	T               float64                    `json:"t"`
	Replies         []*ArchivalSinglePingReply `json:"replies"`
}

// ToArchival returns the archival representation
func (spr *SinglePingResult) ToArchival(begin time.Time) *ArchivalSinglePingResult {
	out := &ArchivalSinglePingResult{
		Delay:           spr.Delay.Seconds(),
		Hostname:        spr.Domain,
		ID:              spr.ID,
		Query:           model.NewArchivalBinaryData(spr.Query),
		QueryID:         int64(spr.QueryID),
		QueryType:       spr.QueryTypeAsString(),
		ResolverAddress: spr.ResolverAddress,
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
