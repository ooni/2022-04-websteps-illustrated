// Package runtimex contains runtime extensions. This package is inspired to
// https://pkg.go.dev/github.com/m-lab/go/rtx, except that it's simpler.
package runtimex

import (
	"fmt"
	"os"
)

// PanicOnError calls panic() if err is not nil.
func PanicOnError(err error, message string) {
	if err != nil {
		panic(fmt.Errorf("%s: %w", message, err))
	}
}

// PanicIfFalse calls panic if assertion is false.
func PanicIfFalse(assertion bool, message string) {
	if !assertion {
		panic(message)
	}
}

// PanicIfTrue calls panic if assertion is true.
func PanicIfTrue(assertion bool, message string) {
	PanicIfFalse(!assertion, message)
}

// PanicIfNil calls panic if the given interface is nil.
func PanicIfNil(v interface{}, message string) {
	PanicIfTrue(v == nil, message)
}

// Must is like PanicOnError but calls os.Exit(1) instead of panic.
func Must(err error, message string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s", message, err.Error())
		os.Exit(1)
	}
}
