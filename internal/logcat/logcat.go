// Package logcat implements a logcat like functionality for ooniprobe.
//
// The logcat dispatches log messages emitted by the OONI engine. We
// internally use a buffered channel where we emit them.
//
// If you do not start any consumer using StartConsumer, we will
// eventually fill the channel and start discarding messages.
//
// Otherwise, we'll dispatch messages to the given consumer. Because
// the consumer is compatible with apex/log, it should be possible
// to just use apex/log.Log's singleton as the consumer.
package logcat

import (
	"context"
	"fmt"
	"io"
	"math"

	"github.com/bassosimone/websteps-illustrated/internal/atomicx"
	"github.com/bassosimone/websteps-illustrated/internal/model"
)

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

var (
	// gq is the global messages queue.
	gq *queue = newqueue()

	// emojis controls whether we're using emojis.
	emojis = atomicx.NewInt32(0)
)

// SetEnableEmojis allows to enable or disable emojis usage.
func SetEnableEmojis(enabled bool) {
	if enabled {
		emojis.Swap(1)
	} else {
		emojis.Swap(0)
	}
}

// queue is the queue containing log messages.
type queue struct {
	// lvl is the log verbosity level.
	lvl *atomicx.Int32

	// q is the real queue.
	q chan *msg
}

// logbuf is the maximum number of messages we could buffer.
const logbuf = 4096

func newqueue() *queue {
	return &queue{
		lvl: atomicx.NewInt32(NOTICE),
		q:   make(chan *msg, logbuf),
	}
}

// msg contains a log message.
type msg struct {
	// level is the message level.
	level int32

	// message is the actual message.
	message string
}

// IncrementLogLevel increments the log level the specified number of times. Use a
// negative increment value to decrement the log level.
func IncrementLogLevel(increment int) {
	gq.incrementLogLevel(increment)
}

// incrementLogLevel increments the log level the specified number of times. Use a
// negative increment value to decrement the log level.
func (q *queue) incrementLogLevel(increment int) {
	if int64(increment) <= math.MinInt32 {
		increment = math.MaxInt32
	} else if int64(increment) >= math.MaxInt32 {
		increment = math.MaxInt32
	}
	q.lvl.Add(int32(increment))
}

// Emit emits a log message to the logcat using the given granularity.
func Emit(level int32, message string) {
	gq.emit(level, message)
}

// emit emits a log message to the queue using the given granularity.
func (q *queue) emit(level int32, message string) {
	if level <= q.lvl.Load() {
		q.pub(level, message)
	}
}

// Emitf is a variation of Emit that allows you to format a message.
func Emitf(level int32, format string, values ...interface{}) {
	gq.emitf(level, format, values...)
}

// emitf is a variation of emit that allows you to format a message.
func (q *queue) emitf(level int32, format string, values ...interface{}) {
	if level <= q.lvl.Load() {
		q.pub(level, fmt.Sprintf(format, values...))
	}
}

// pub publishes a message to the queue.
func (q *queue) pub(level int32, message string) {
	m := &msg{
		level:   level,
		message: message,
	}
	select {
	case q.q <- m:
	default:
		// just ignore this message, as documented
	}
}

// queue returns the message queue to wait on.
func (q *queue) queue() <-chan *msg {
	return q.q
}

// StartConsumer starts a consumer that consumes log messages
// and dispatches them to the given logger. The consumer
// will gracefully exit when the provided context expires.
func StartConsumer(ctx context.Context, logger model.Logger) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-gq.queue():
				switch m.level {
				case WARNING:
					logger.Warn(m.message)
				case INFO, NOTICE:
					logger.Info(m.message)
				default:
					logger.Debug(m.message)
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

// DefaultLogger returns the default model.Logger.
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

func hasEmojis() bool {
	return emojis.Load() != 0
}

var bugemoji = map[bool]string{
	true:  "🐛 ",
	false: "BUG:      ",
}

// Bug is a convenience function for emitting a log message about a bug. By default
// this log message will be at WARN level. We may be continuing to run after we notice
// there's a bug, but subsequent results may be influenced by that.
func Bug(message string) {
	Warn(bugemoji[hasEmojis()] + message)
}

// Bugf is like Bug but allows formatting a message.
func Bugf(format string, value ...interface{}) {
	Warnf(bugemoji[hasEmojis()]+format, value...)
}

var cacheemoji = map[bool]string{
	true:  "👛 ",
	false: "CACHE:    ",
}

// Cache is a convenience function for emitting messages related to the cache. The user
// should not see these messages by default unless they want more details. For this
// reason we emit this kind of messages at the INFO level.
func Cache(message string) {
	Info(cacheemoji[hasEmojis()] + message)
}

// Cachef is like Cache but allows formatting a message.
func Cachef(format string, value ...interface{}) {
	Infof(cacheemoji[hasEmojis()]+format, value...)
}

var shrugemoji = map[bool]string{
	true:  "🤷 ",
	false: "WTF:      ",
}

// Shrug is a convenience function for emitting log messages detailing that something
// not under our control went wrong and we don't know what to do about this. We emit
// these messaeges as warnings because we users to let us know about these errors.
func Shrug(message string) {
	Warn(shrugemoji[hasEmojis()] + message)
}

// Shrugf is like Shrug but allows formatting a message,
func Shrugf(format string, value ...interface{}) {
	Warnf(shrugemoji[hasEmojis()]+format, value...)
}

var stepemoji = map[bool]string{
	true:  "📌 ",
	false: "STEP:     ",
}

// Step is a convenience function for emitting log messages related to one
// of several steps within an experiment. These are NOTICEs.
func Step(message string) {
	Notice(stepemoji[hasEmojis()] + message)
}

// Stepf is like Step but allows formatting messages.
func Stepf(format string, value ...interface{}) {
	Noticef(stepemoji[hasEmojis()]+format, value...)
}

var substepemoji = map[bool]string{
	true:  "📎 ",
	false: "SUBSTEP:  ",
}

// Substep is a convenience function for emitting log messages related to one
// of several substeps within a step. These are NOTICEs.
func Substep(message string) {
	Notice(substepemoji[hasEmojis()] + message)
}

// Substepf is like Substep but allows formatting messages.
func Substepf(format string, value ...interface{}) {
	Noticef(substepemoji[hasEmojis()]+format, value...)
}

var newinputemoji = map[bool]string{
	true:  "✨ ",
	false: "NEWINPUT: ",
}

// NewInput is the function to call when you are an experiment and you
// receive new input. This is also part of the NOTICEs.
func NewInput(message string) {
	Notice(newinputemoji[hasEmojis()] + message)
}

// NewInputf is like NewInput but allows formatting messages.
func NewInputf(format string, value ...interface{}) {
	Noticef(newinputemoji[hasEmojis()]+format, value...)
}
