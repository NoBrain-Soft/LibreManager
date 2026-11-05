package collect

import (
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Encoder limits.
const (
	DefaultMaxSeries = 10000
	maxLabels        = 16
	maxLabelValue    = 256
	maxMetricName    = 128
)

// droppedSeriesMetric counts samples the encoder dropped because the series
// cap was reached or the sample was invalid. It is exempt from the cap and
// only sent once something was dropped.
const droppedSeriesMetric = "stellwerk_agent_series_dropped_total"

// Encoder turns samples into delta-friendly MetricsBatch messages
// (metrics.proto): on the live stream each series is defined once (SeriesDef
// id -> name + labels) and afterwards referenced by its id only. Ids are
// stable for the lifetime of a stream and never reused; Reset must be called
// whenever a new Connect stream starts.
//
// At most maxSeries series are defined per stream; samples of further new
// series are dropped and counted (Dropped, and the
// stellwerk_agent_series_dropped_total series). Samples with invalid names
// or non-finite values are dropped too. Label values are sanitized (valid
// UTF-8, ≤ 256 bytes). An Encoder is safe for concurrent use.
type Encoder struct {
	mu        sync.Mutex
	maxSeries int
	ids       map[string]uint32
	nextID    uint32
	droppedID uint32
	dropped   uint64
	key       []byte
}

// NewEncoder returns an encoder capping series per stream at maxSeries
// (<= 0: DefaultMaxSeries).
func NewEncoder(maxSeries int) *Encoder {
	if maxSeries <= 0 {
		maxSeries = DefaultMaxSeries
	}
	return &Encoder{maxSeries: maxSeries, ids: make(map[string]uint32)}
}

// Reset forgets all series definitions; call it on every new stream.
func (e *Encoder) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.ids)
	e.nextID = 0
	e.droppedID = 0
}

// Dropped returns the total number of dropped samples since creation.
func (e *Encoder) Dropped() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dropped
}

// Series returns the number of series defined on the current stream.
func (e *Encoder) Series() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.ids)
}

// Encode builds a live-stream batch: defs only for series not yet sent on
// this stream.
func (e *Encoder) Encode(ts time.Time, samples []Sample) *agentv1.MetricsBatch {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &agentv1.MetricsBatch{TimestampMs: ts.UnixMilli()}
	inBatch := make(map[uint32]struct{}, len(samples))
	b.Points = make([]*agentv1.Point, 0, len(samples))
	for i := range samples {
		s, ok := normalize(samples[i])
		if !ok {
			e.dropped++
			continue
		}
		e.key = seriesKey(e.key[:0], s)
		id, known := e.ids[string(e.key)]
		if !known {
			if len(e.ids) >= e.maxSeries {
				e.dropped++
				continue
			}
			e.nextID++
			id = e.nextID
			e.ids[string(e.key)] = id
			b.Defs = append(b.Defs, seriesDef(id, s))
		}
		if _, dup := inBatch[id]; dup {
			continue
		}
		inBatch[id] = struct{}{}
		b.Points = append(b.Points, &agentv1.Point{SeriesId: id, Value: s.Value})
	}
	if e.dropped > 0 {
		if e.droppedID == 0 {
			e.nextID++
			e.droppedID = e.nextID
			b.Defs = append(b.Defs, &agentv1.SeriesDef{Id: e.droppedID, Name: droppedSeriesMetric})
		}
		b.Points = append(b.Points, &agentv1.Point{SeriesId: e.droppedID, Value: float64(e.dropped)})
	}
	return b
}

// EncodeSelfContained builds a replayable batch (replay = true) whose defs
// cover every point, with ids local to the batch. It does not touch the
// live-stream state and is used for the offline spool.
func (e *Encoder) EncodeSelfContained(ts time.Time, samples []Sample) *agentv1.MetricsBatch {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &agentv1.MetricsBatch{TimestampMs: ts.UnixMilli(), Replay: true}
	local := make(map[string]uint32, len(samples))
	b.Defs = make([]*agentv1.SeriesDef, 0, len(samples))
	b.Points = make([]*agentv1.Point, 0, len(samples))
	var key []byte
	for i := range samples {
		s, ok := normalize(samples[i])
		if !ok {
			e.dropped++
			continue
		}
		key = seriesKey(key[:0], s)
		if _, dup := local[string(key)]; dup {
			continue
		}
		if len(local) >= e.maxSeries {
			e.dropped++
			continue
		}
		id := uint32(len(local) + 1) //nolint:gosec // bounded by maxSeries
		local[string(key)] = id
		b.Defs = append(b.Defs, seriesDef(id, s))
		b.Points = append(b.Points, &agentv1.Point{SeriesId: id, Value: s.Value})
	}
	if e.dropped > 0 {
		id := uint32(len(local) + 1) //nolint:gosec // bounded by maxSeries
		b.Defs = append(b.Defs, &agentv1.SeriesDef{Id: id, Name: droppedSeriesMetric})
		b.Points = append(b.Points, &agentv1.Point{SeriesId: id, Value: float64(e.dropped)})
	}
	return b
}

func seriesDef(id uint32, s Sample) *agentv1.SeriesDef {
	d := &agentv1.SeriesDef{Id: id, Name: s.Name}
	if len(s.Labels) > 0 {
		d.Labels = make([]*agentv1.Label, len(s.Labels))
		for i, l := range s.Labels {
			d.Labels[i] = &agentv1.Label{Name: l.Name, Value: l.Value}
		}
	}
	return d
}

// seriesKey appends a unique key for name + labels (labels sorted).
func seriesKey(dst []byte, s Sample) []byte {
	dst = append(dst, s.Name...)
	for _, l := range s.Labels {
		dst = append(dst, 0xff)
		dst = append(dst, l.Name...)
		dst = append(dst, 0xfe)
		dst = append(dst, l.Value...)
	}
	return dst
}

// normalize validates a sample and returns it with sorted, sanitized
// labels. The input is not modified.
func normalize(s Sample) (Sample, bool) {
	if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
		return s, false
	}
	if !validMetricName(s.Name) || len(s.Labels) > maxLabels {
		return s, false
	}
	needCopy := !slices.IsSortedFunc(s.Labels, func(a, b Label) int { return strings.Compare(a.Name, b.Name) })
	for i, l := range s.Labels {
		if !validLabelName(l.Name) {
			return s, false
		}
		if i > 0 && s.Labels[i-1].Name == l.Name {
			return s, false
		}
		if osutil.Clean(l.Value, maxLabelValue) != l.Value {
			needCopy = true
		}
	}
	if needCopy {
		ls := make([]Label, len(s.Labels))
		for i, l := range s.Labels {
			ls[i] = Label{Name: l.Name, Value: osutil.Clean(l.Value, maxLabelValue)}
		}
		sortLabels(ls)
		for i := 1; i < len(ls); i++ {
			if ls[i-1].Name == ls[i].Name {
				return s, false
			}
		}
		s.Labels = ls
	}
	return s, true
}

func validMetricName(n string) bool {
	if n == "" || len(n) > maxMetricName {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func validLabelName(n string) bool {
	if n == "" || len(n) > 64 || strings.HasPrefix(n, "__") {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}
