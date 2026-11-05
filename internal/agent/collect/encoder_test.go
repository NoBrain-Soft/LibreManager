package collect

import (
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// resolve maps a batch back to name{labels} -> value using defs (which must
// be known from this batch or earlier ones on the stream).
func resolve(t *testing.T, defs map[uint32]string, b *agentv1.MetricsBatch) map[string]float64 {
	t.Helper()
	for _, d := range b.GetDefs() {
		if _, dup := defs[d.GetId()]; dup {
			t.Fatalf("series id %d defined twice on one stream", d.GetId())
		}
		s := Sample{Name: d.GetName()}
		for _, l := range d.GetLabels() {
			s.Labels = append(s.Labels, Label{l.GetName(), l.GetValue()})
		}
		defs[d.GetId()] = key(s)
	}
	out := map[string]float64{}
	for _, p := range b.GetPoints() {
		k, ok := defs[p.GetSeriesId()]
		if !ok {
			t.Fatalf("point references undefined series %d", p.GetSeriesId())
		}
		out[k] = p.GetValue()
	}
	return out
}

func TestEncoderLiveStream(t *testing.T) {
	ts := time.UnixMilli(1_800_000_000_123)
	e := NewEncoder(0)
	round1 := []Sample{
		sample("stellwerk_load1", 0.5),
		sample("stellwerk_cpu_seconds_total", 10, "mode", "user"),
		sample("stellwerk_cpu_seconds_total", 20, "mode", "idle"),
	}
	b1 := e.Encode(ts, round1)
	if b1.GetTimestampMs() != ts.UnixMilli() || b1.GetReplay() {
		t.Fatalf("batch header %v", b1)
	}
	if len(b1.GetDefs()) != 3 || len(b1.GetPoints()) != 3 {
		t.Fatalf("round 1: %d defs, %d points", len(b1.GetDefs()), len(b1.GetPoints()))
	}
	defs := map[uint32]string{}
	got := resolve(t, defs, b1)
	expect(t, got, map[string]float64{"stellwerk_load1": 0.5, "stellwerk_cpu_seconds_total{mode=idle}": 20})

	// Round 2: known series carry no defs; one new series is defined.
	round2 := append(round1[:3:3], sample("stellwerk_load5", 0.25))
	round2[0].Value = 0.9
	b2 := e.Encode(ts.Add(15*time.Second), round2)
	if len(b2.GetDefs()) != 1 || b2.GetDefs()[0].GetName() != "stellwerk_load5" {
		t.Fatalf("round 2 defs = %v", b2.GetDefs())
	}
	got = resolve(t, defs, b2)
	expect(t, got, map[string]float64{"stellwerk_load1": 0.9, "stellwerk_load5": 0.25})

	// Ids are stable on the stream.
	if b1.GetPoints()[0].GetSeriesId() != b2.GetPoints()[0].GetSeriesId() {
		t.Fatal("series id changed within a stream")
	}

	// After Reset every series is defined again.
	e.Reset()
	b3 := e.Encode(ts, round1)
	if len(b3.GetDefs()) != 3 {
		t.Fatalf("after reset: %d defs", len(b3.GetDefs()))
	}
	resolve(t, map[uint32]string{}, b3)
}

func TestEncoderCapAndValidation(t *testing.T) {
	e := NewEncoder(2)
	samples := []Sample{
		sample("stellwerk_a", 1),
		sample("stellwerk_b", 2),
		sample("stellwerk_c", 3),                                       // over cap
		sample("stellwerk_d", math.NaN()),                              // non-finite
		sample("stellwerk_e", math.Inf(1)),                             // non-finite
		{Name: "bad-name", Value: 1},                                   // invalid name
		{Name: "stellwerk_f", Labels: []Label{{"__x", "y"}}},           // reserved label
		{Name: "stellwerk_g", Labels: []Label{{"a", "1"}, {"a", "2"}}}, // duplicate label
		sample("stellwerk_a", 9),                                       // duplicate in batch: deduped, not a drop
	}
	b := e.Encode(time.Now(), samples)
	defs := map[uint32]string{}
	got := resolve(t, defs, b)
	expect(t, got, map[string]float64{"stellwerk_a": 1, "stellwerk_b": 2, droppedSeriesMetric: 6})
	if len(got) != 3 || e.Dropped() != 6 || e.Series() != 2 {
		t.Fatalf("got %v, dropped %d, series %d", got, e.Dropped(), e.Series())
	}
	// The drop counter keeps its id and is not re-defined.
	b2 := e.Encode(time.Now(), []Sample{sample("stellwerk_a", 1), sample("stellwerk_z", 1)})
	got = resolve(t, defs, b2)
	expect(t, got, map[string]float64{droppedSeriesMetric: 7})
}

func TestEncoderSanitizesLabels(t *testing.T) {
	e := NewEncoder(0)
	s := Sample{Name: "stellwerk_filesystem_size_bytes", Labels: []Label{
		{"mountpoint", "/mnt/\xff" + strings.Repeat("x", 400)},
		{"device", "/dev/sda1"},
	}, Value: 1}
	b := e.Encode(time.Now(), []Sample{s})
	if _, err := proto.Marshal(b); err != nil {
		t.Fatalf("batch does not marshal: %v", err)
	}
	ls := b.GetDefs()[0].GetLabels()
	if ls[0].GetName() != "device" || len(ls[1].GetValue()) > maxLabelValue {
		t.Fatalf("labels not sorted/sanitized: %v", ls)
	}
	if s.Labels[0].Name != "mountpoint" {
		t.Fatal("input sample was modified")
	}
}

func TestEncoderSelfContained(t *testing.T) {
	e := NewEncoder(100)
	live := e.Encode(time.Now(), []Sample{sample("stellwerk_load1", 1)})
	samples := []Sample{
		sample("stellwerk_load1", 1),
		sample("stellwerk_cpu_seconds_total", 2, "mode", "user"),
		sample("stellwerk_cpu_seconds_total", 2, "mode", "user"),
	}
	b := e.EncodeSelfContained(time.UnixMilli(42), samples)
	if !b.GetReplay() || b.GetTimestampMs() != 42 {
		t.Fatalf("header %v", b)
	}
	got := resolve(t, map[uint32]string{}, b)
	if len(got) != 2 || len(b.GetDefs()) != 2 {
		t.Fatalf("self-contained batch: %v", got)
	}
	// Live stream state is untouched: the next live batch has no new defs.
	next := e.Encode(time.Now(), []Sample{sample("stellwerk_load1", 1)})
	if len(next.GetDefs()) != 0 || next.GetPoints()[0].GetSeriesId() != live.GetPoints()[0].GetSeriesId() {
		t.Fatalf("self-contained encode disturbed live state: %v", next)
	}
	// Round-trips through the wire format.
	data, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var back agentv1.MetricsBatch
	if err := proto.Unmarshal(data, &back); err != nil || !proto.Equal(&back, b) {
		t.Fatalf("round trip: %v", err)
	}
}

func BenchmarkEncode(b *testing.B) {
	samples := make([]Sample, 0, 400)
	for i := range 400 {
		samples = append(samples, sample("stellwerk_disk_read_bytes_total", float64(i), "device", "sd"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	e := NewEncoder(0)
	e.Encode(time.Now(), samples)
	b.ReportAllocs()
	for b.Loop() {
		e.Encode(time.Now(), samples)
	}
}
