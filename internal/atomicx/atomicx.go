// Package atomicx extends sync/atomic.
//
// Sync/atomic fails when using int64 atomic operations on 32 bit platforms
// when the access is not aligned. As specified in the documentation, in
// fact, "it is the caller's responsibility to arrange for 64-bit alignment
// of 64-bit words accessed atomically". For more information on this
// issue, see https://golang.org/pkg/sync/atomic/#pkg-note-BUG.
//
// As explained in CONTRIBUTING.md, probe-cli SHOULD use this package rather
// than sync/atomic to avoid these alignment issues on 32 bit.
//
// It is of course possible to write atomic code using 64 bit variables on a
// 32 bit platform, but that's difficult to do correctly. This package
// provides an easier-to-use interface. We allocate structures so to ensure
// that 64 bit values are always boundary aligned.
package atomicx

import "sync/atomic"

// Int64 is an int64 with atomic semantics.
type Int64 struct {
	// v is the underlying value.
	v int64
}

// NewInt64 creates a new Int64 with the given value.
func NewInt64(value int64) *Int64 {
	return &Int64{
		v: value,
	}
}

// Add behaves like atomic.AddInt64.
func (i64 *Int64) Add(delta int64) int64 {
	return atomic.AddInt64(&i64.v, delta)
}

// Load behaves like atomic.LoadInt64.
func (i64 *Int64) Load() int64 {
	return atomic.LoadInt64(&i64.v)
}

// Swap behaves like atomic.SwapInt64.
func (i64 *Int64) Swap(val int64) int64 {
	return atomic.SwapInt64(&i64.v, val)
}
