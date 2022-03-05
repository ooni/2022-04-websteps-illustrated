package websteps

//
// TH
//
// Test helper client and server.
//

import (
	"context"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/measurex"
)

// th runs the test helper client in a background goroutine.
func (c *Client) th(ctx context.Context, cur *measurex.URLMeasurement,
	plan []*measurex.EndpointPlan) <-chan *measurex.URLMeasurement {
	out := make(chan *measurex.URLMeasurement)
	// XXX: we must parse outside of the child function
	go func() {
		defer close(out)
		time.Sleep(2 * time.Second)
	}()
	return out
}
