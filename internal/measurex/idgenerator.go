package measurex

//
// ID generator
//
// Generates unique IDs for measurements.
//

import "github.com/bassosimone/websteps-illustrated/internal/atomicx"

// IDGenerator generates unique IDs for measurements.
type IDGenerator struct {
	c *atomicx.Int64
}

// NewIDGenerator creates a new IDGenerator.
func NewIDGenerator() *IDGenerator {
	return &IDGenerator{
		c: &atomicx.Int64{},
	}
}

// Next returns the next unique ID.
func (g *IDGenerator) Next() int64 {
	return g.c.Add(1)
}
