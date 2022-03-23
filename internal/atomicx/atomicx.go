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
// provides an easier-to-use interface. We use allocated
// structures protected by a mutex that encapsulate a int64 value.
package atomicx

import (
	"sync"
	"sync/atomic"
)

/*
	TODO(bassosimone): Go documentation states that:

	  On ARM, 386, and 32-bit MIPS, it is the caller's responsibility
	  to arrange for 64-bit alignment of 64-bit words accessed atomically. The
	  first word in a variable or in an allocated struct, array, or slice can
	  be relied upon to be 64-bit aligned.

	Would this mean that Int64 could use sync/atomic directly if it
	only contained `v` as its first and unique element?

	See https://pkg.go.dev/sync/atomic#pkg-note-BUG
*/

// Int64 is an int64 with atomic semantics.
type Int64 struct {
	// mu provides mutual exclusion.
	mu sync.Mutex

	// v is the underlying value.
	v int64
}

// NewInt64 creates a new Int64 with the given value.
func NewInt64(value int64) *Int64 {
	return &Int64{
		mu: sync.Mutex{},
		v:  value,
	}
}

// Add behaves like atomic.AddInt64.
func (i64 *Int64) Add(delta int64) int64 {
	i64.mu.Lock()
	defer i64.mu.Unlock()
	i64.v += delta
	return i64.v
}

// Load behaves like atomic.LoadInt64.
func (i64 *Int64) Load() (v int64) {
	return i64.Add(0)
}

// Int32 is an int32 with atomic semantics.
type Int32 struct {
	// v is the underlying value.
	v int32
}

// NewInt32 creates an atomic int32 with the given value.
func NewInt32(value int32) *Int32 {
	return &Int32{v: value}
}

// Add behaves like Int64.Add.
func (v *Int32) Add(delta int32) int32 {
	return atomic.AddInt32(&v.v, delta)
}

// Load behaves like Int64.Load.
func (v *Int32) Load() int32 {
	return atomic.LoadInt32(&v.v)
}

// Swap behaves like atomic.SwapInt32
func (v *Int32) Swap(other int32) int32 {
	return atomic.SwapInt32(&v.v, other)
}
