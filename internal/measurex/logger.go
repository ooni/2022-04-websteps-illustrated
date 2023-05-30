package measurex

//
// Logger
//
// Code for logging
//

import (
	"fmt"
	"sync"
	"time"

	"github.com/ooni/2022-04-websteps-illustrated/internal/logcat"
	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
)

// NewOperationLogger creates a new logger that logs
// about an in-progress operation.
func NewOperationLogger(format string, v ...interface{}) *OperationLogger {
	ol := &OperationLogger{
		sighup:  make(chan interface{}),
		once:    &sync.Once{},
		message: fmt.Sprintf(format, v...),
		t:       time.Now(),
		wg:      &sync.WaitGroup{},
	}
	ol.wg.Add(1)
	go ol.logloop()
	return ol
}

// OperationLogger logs about an in-progress operation
type OperationLogger struct {
	message string
	once    *sync.Once
	sighup  chan interface{}
	t       time.Time
	wg      *sync.WaitGroup
}

func (ol *OperationLogger) logloop() {
	defer ol.wg.Done()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		logcat.Noticef("%s... in progress", ol.message)
	case <-ol.sighup:
		// we'll emit directly in stop
	}
}

func (ol *OperationLogger) Stop(err error) {
	ol.once.Do(func() {
		close(ol.sighup)
		ol.wg.Wait()
		d := time.Since(ol.t)
		es := model.ErrorToStringOrOK(err)
		logcat.Noticef("%s... %s (in %s)", ol.message, es, d)
	})
}
