package livecollect

import (
	"errors"
	"sync"
	"time"

	"github.com/torjan0/cirewind/internal/model"
)

// checkedClock serializes access to an injected clock, retains the last valid
// value as a no-panic placeholder, and latches the first invalid result. The
// caller must inspect Err before normalizing or committing the collection.
type checkedClock struct {
	mu       sync.Mutex
	source   Clock
	last     time.Time
	firstErr error
}

func newCheckedClock(source Clock, initial time.Time) *checkedClock {
	return &checkedClock{source: source, last: initial.UTC().Round(0)}
}

func (c *checkedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := c.source().UTC().Round(0)
	if value.IsZero() {
		if c.firstErr == nil {
			c.firstErr = &ClockError{Operation: "returned zero time", Err: errors.New("timestamp is zero")}
		}
		return c.last
	}
	c.last = value
	return value
}

func (c *checkedClock) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstErr
}

func initialClockInstant(source Clock) (model.Instant, time.Time, error) {
	value := source().UTC().Round(0)
	instant, err := model.NewInstant(value)
	if err != nil {
		return model.Instant{}, time.Time{}, &ClockError{Operation: "initial sample", Err: err}
	}
	return instant, value, nil
}
