// Package logcat implements a logcat-like functionality for ooniprobe.
//
// The logcat dispatches log messages emitted by the OONI engine. We
// internally store log messages on a ring buffer that mobile apps will
// be able to access in order to get recent logs. To get recent logs,
// use the Read public function, which returns them.
//
// We also allow streaming logs to apex/log-like loggers. To this end,
// you need to call StartConsumer. The consumer is a background goroutine
// that extracts and dispatches logger to an apex/log-like logger. You
// provide StartConsumer with a context. When the context is done, we'll
// automatically de-register the consumer. The logcat will buffer messages
// to consumers in case they're not reading them fast enough. When the
// buffer is full, we'll discard new messages.
//
// This package supports emitting log messages containing emojis, which
// you can configure on a per-consumer-specific basis.
package logcat

import (
	"container/ring"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bassosimone/websteps-illustrated/internal/atomicx"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

// These values control the log level.
const (
	// WARNING is only emitted when a specific operation fails and
	// this fact may have implications on subsequent operations.
	WARNING = iota

	// NOTICE is the standard logging level where we only emit
	// a minimal amount to message to convey progress.
	NOTICE

	// INFO contains informational messages explaining to the user
	// what the program is doing and why.
	INFO

	// DEBUG increases the software verbosity compared to INFO
	// but not at the level of detail provided by TRACE.
	DEBUG

	// TRACE provides the most detailed level of logging where we
	// show individual operations that we perform.
	TRACE
)

// VERBOSITY_MASK extracts verbosity information from a log message and
// separates this information from extra information.
const VERBOSITY_MASK = WARNING | NOTICE | INFO | DEBUG | TRACE

// These values allow to attach extra meaning to log messages, which is
// used to generate output containing emojis (if they're enabled).
const (
	// BUG indicates that this log message refers to a bug.
	BUG = (1 + iota) << 3

	// CACHE indicates a message from the cache.
	CACHE

	// STEP is the beginning of a measurement step.
	STEP

	// SUBSTEP is the beginning of a measurement substep.
	SUBSTEP

	// NEW_INPUT is a message indicating we're starting a new run of
	// an experiment with the provided input.
	NEW_INPUT

	// SHRUG is a message about an unexpected situation that is out of our
	// control (as opposed to BUG, which is under our control.)
	SHRUG
)

// EXTRA_FLAGS_MASK extracts extra flags from a log message. The extra
// flags typically contains information for emojis.
const EXTRA_FLAGS_MASK = ^VERBOSITY_MASK

// gq is the global messages queue.
var gq *queue = newqueue()

// subscriber is a subscriber for streaming messages.
type subscriber struct {
	ch chan *Msg
}

// queue is the queue containing log messages.
type queue struct {
	// lvl is the log verbosity level.
	lvl *atomicx.Int64

	// mu provides mutual exclusion.
	mu sync.Mutex

	// r is the ring for messages.
	r *ring.Ring

	// subs cntains the subscribers.
	subs []*subscriber
}

// logbuf is the maximum number of messages we could buffer. Assuming that
// each message is 1024 bytes in size, the queue will occupy 4 MiB.
const logbuf = 1 << 12

func newqueue() *queue {
	return &queue{
		lvl:  atomicx.NewInt64(NOTICE),
		mu:   sync.Mutex{},
		r:    ring.New(logbuf),
		subs: nil,
	}
}

// Msg contains a log message.
type Msg struct {
	// Time is the Time when we collected the message.
	Time time.Time

	// Level is the message Level. It may also encode emoji
	// related information, so you need to be prepared to
	// separate the log Level from extra information.
	Level int64

	// Message is the actual Message.
	Message string
}

// asMsg is an utility function for creating a asMsg of a *Msg to a Msg.
func (m *Msg) asMsg() Msg {
	return Msg{
		Time:    m.Time,
		Level:   m.Level,
		Message: m.Message,
	}
}

// IncrementLogLevel increments the log level the specified number of times. Use a
// negative increment value to decrement the log level.
func IncrementLogLevel(increment int) {
	gq.incrementLogLevel(increment)
}

// incrementLogLevel increments the log level the specified number of times. Use a
// negative increment value to decrement the log level.
func (q *queue) incrementLogLevel(increment int) {
	// Implementation note: multiple callers of this function will not cause data
	// races but we may nonetheless end up with inconsistent results. Because we are
	// not planning on racing in incrementing the verbosity level, this is fine.
	v := q.lvl.Load()
	v += int64(increment)
	if v <= WARNING {
		v = WARNING
	} else if v >= TRACE {
		v = TRACE
	}
	q.lvl.Swap(v)
}

// Emit emits a log message to the logcat using the given level.
func Emit(level int64, message string) {
	gq.emit(level, message)
}

func (q *queue) emit(level int64, message string) {
	if (level & VERBOSITY_MASK) <= q.lvl.Load() {
		q.pub(level, message)
	}
}

// Emitf is a variation of Emit that allows you to format a message.
func Emitf(level int64, format string, values ...interface{}) {
	gq.emitf(level, format, values...)
}

func (q *queue) emitf(level int64, format string, values ...interface{}) {
	if (level & VERBOSITY_MASK) <= q.lvl.Load() {
		q.pub(level, fmt.Sprintf(format, values...))
	}
}

// pub publishes a message to the queue.
func (q *queue) pub(level int64, message string) {
	m := &Msg{
		Time:    time.Now(),
		Level:   level,
		Message: message,
	}
	q.mu.Lock()
	// 1. store the message into the ring
	q.r.Value = m
	q.r = q.r.Next()
	// 2. dispatch the message to consumers
	for _, s := range q.subs {
		select {
		case s.ch <- m:
		default:
			// could not deliver message
		}
	}
	q.mu.Unlock()
}

// Read reads all the buffered log messages.
func Read() []Msg {
	return gq.read()
}

func (q *queue) read() []Msg {
	q.mu.Lock()
	out := []Msg{}
	q.r.Do(func(i interface{}) {
		if i == nil {
			return
		}
		msg, good := i.(*Msg)
		if !good {
			return
		}
		out = append(out, msg.asMsg())
	})
	q.mu.Unlock()
	return out
}

func (q *queue) subscribe(s *subscriber) {
	q.mu.Lock()
	q.subs = append(q.subs, s)
	q.mu.Unlock()
}

func (q *queue) unsubscribe(s *subscriber) {
	q.mu.Lock()
	ns := []*subscriber{}
	for _, rs := range q.subs {
		if s != rs {
			ns = append(ns, rs)
		}
	}
	q.subs = ns
	q.mu.Unlock()
}

var emojimap = map[int64]string{
	BUG:       "🐛 ",
	CACHE:     "👛 ",
	SHRUG:     "🤷 ",
	STEP:      "📌 ",
	SUBSTEP:   "📎 ",
	NEW_INPUT: "✨ ",
}

// StartConsumer starts a consumer that consumes log messages
// and dispatches them to the given logger. The consumer
// will gracefully exit when the provided context expires.
func StartConsumer(ctx context.Context, logger model.Logger, emojis bool) {
	go func() {
		s := &subscriber{
			ch: make(chan *Msg, logbuf),
		}
		gq.subscribe(s)
		defer gq.unsubscribe(s)
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-s.ch:
				var prefix string
				if emojis {
					prefix = emojimap[m.Level&EXTRA_FLAGS_MASK]
					if prefix == "" {
						prefix = "   "
					}
				}
				switch m.Level & VERBOSITY_MASK {
				case WARNING:
					logger.Warn(prefix + m.Message)
				case INFO, NOTICE:
					logger.Info(prefix + m.Message)
				default:
					logger.Debug(prefix + m.Message)
				}
			}
		}
	}()
}

// Warn emits a WARNING message.
func Warn(message string) {
	Emit(WARNING, message)
}

// Warnf formats and emits a WARNING message.
func Warnf(format string, values ...interface{}) {
	Emitf(WARNING, format, values...)
}

// Notice emits a NOTICE message.
func Notice(message string) {
	Emit(NOTICE, message)
}

// Noticef formats and emits a NOTICE message.
func Noticef(format string, values ...interface{}) {
	Emitf(NOTICE, format, values...)
}

// Info emits an INFO message.
func Info(message string) {
	Emit(INFO, message)
}

// Infof formats and emits an INFO message.
func Infof(format string, values ...interface{}) {
	Emitf(INFO, format, values...)
}

// Debug emits a DEBUG message.
func Debug(message string) {
	Emit(DEBUG, message)
}

// Debugf formats and emits a DEBUG message.
func Debugf(format string, values ...interface{}) {
	Emitf(DEBUG, format, values...)
}

// Trace emits a TRACE message.
func Trace(message string) {
	Emit(TRACE, message)
}

// Tracef formats and emits a TRACE message.
func Tracef(format string, values ...interface{}) {
	Emitf(TRACE, format, values...)
}

// DefaultLogger returns the default model.Logger. This logger will just
// print the provided messages to the given io.Writer.
func DefaultLogger(w io.Writer) model.Logger {
	return &defaultLogger{
		w: w,
	}
}

// defaultLogger is the default model.Logger.
type defaultLogger struct {
	w io.Writer
}

// Debug implements DebugLogger.Debug
func (dl *defaultLogger) Debug(msg string) {
	fmt.Fprint(dl.w, msg+"\n")
}

// Debugf implements DebugLogger.Debugf
func (dl *defaultLogger) Debugf(format string, v ...interface{}) {
	fmt.Fprintf(dl.w, format+"\n", v...)
}

// Info implements InfoLogger.Info
func (dl *defaultLogger) Info(msg string) {
	fmt.Fprint(dl.w, msg+"\n")
}

// Infov implements InfoLogger.Infov
func (dl *defaultLogger) Infof(format string, v ...interface{}) {
	fmt.Fprintf(dl.w, format+"\n", v...)
}

// Warn implements Logger.Warn
func (dl *defaultLogger) Warn(msg string) {
	fmt.Fprint(dl.w, msg+"\n")
}

// Warnf implements Logger.Warnf
func (dl *defaultLogger) Warnf(format string, v ...interface{}) {
	fmt.Fprintf(dl.w, format+"\n", v...)
}

// Bug is a convenience function for emitting a log message about a bug. By default
// this log message will be at WARNING level. We may be continuing to run after we notice
// there's a bug, but subsequent results may be influenced by that.
func Bug(message string) {
	Emit(WARNING|BUG, message)
}

// Bugf is like Bug but allows formatting a message.
func Bugf(format string, value ...interface{}) {
	Emitf(WARNING|BUG, format, value...)
}

// Cache is a convenience function for emitting messages related to the cache. The user
// should not see these messages by default unless they want more details. For this
// reason we emit this kind of messages at the INFO level.
func Cache(message string) {
	Emit(INFO|CACHE, message)
}

// Cachef is like Cache but allows formatting a message.
func Cachef(format string, value ...interface{}) {
	Emitf(INFO|CACHE, format, value...)
}

// Shrug is a convenience function for emitting log messages detailing that something
// not under our control went wrong and we don't know what to do about this. We emit
// these messaeges as warnings because we users to let us know about these errors.
func Shrug(message string) {
	Emit(WARNING|SHRUG, message)
}

// Shrugf is like Shrug but allows formatting a message,
func Shrugf(format string, value ...interface{}) {
	Emitf(WARNING|SHRUG, format, value...)
}

// Step is a convenience function for emitting log messages related to one
// of several steps within an experiment. These are NOTICEs.
func Step(message string) {
	Emitf(NOTICE|STEP, message)
}

// Stepf is like Step but allows formatting messages.
func Stepf(format string, value ...interface{}) {
	Emitf(NOTICE|STEP, format, value...)
}

// Substep is a convenience function for emitting log messages related to one
// of several substeps within a step. These are NOTICEs.
func Substep(message string) {
	Emitf(NOTICE|SUBSTEP, message)
}

// Substepf is like Substep but allows formatting messages.
func Substepf(format string, value ...interface{}) {
	Emitf(NOTICE|SUBSTEP, format, value...)
}

// NewInput is the function to call when you are an experiment and you
// receive new input. This is also part of the NOTICEs.
func NewInput(message string) {
	Emit(NOTICE|NEW_INPUT, message)
}

// NewInputf is like NewInput but allows formatting messages.
func NewInputf(format string, value ...interface{}) {
	Emitf(NOTICE|NEW_INPUT, format, value...)
}
