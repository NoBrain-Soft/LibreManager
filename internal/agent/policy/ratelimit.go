package policy

import (
	"sync"
	"time"
)

// RateLimiter is a sliding one-minute window limiter for jobs
// (limits.max_jobs_per_minute). Core and helper each run one.
type RateLimiter struct {
	mu    sync.Mutex
	limit int
	times []time.Time
	now   func() time.Time
}

// NewRateLimiter returns a limiter allowing limit events per minute.
func NewRateLimiter(limit int, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{limit: limit, now: now}
}

// Allow records an event and reports whether it is within the limit.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cutoff := now.Add(-time.Minute)
	i := 0
	for i < len(r.times) && !r.times[i].After(cutoff) {
		i++
	}
	r.times = r.times[i:]
	if len(r.times) >= r.limit {
		return false
	}
	r.times = append(r.times, now)
	return true
}
