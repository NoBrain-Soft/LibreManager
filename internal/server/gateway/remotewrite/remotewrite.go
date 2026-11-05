// Package remotewrite sends samples to VictoriaMetrics using the Prometheus
// remote-write protocol (snappy-compressed protobuf WriteRequest). The
// protobuf is hand-encoded to avoid pulling in the Prometheus module.
package remotewrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

// Label is a name/value pair.
type Label struct{ Name, Value string }

// Series is one time series with samples.
type Series struct {
	// Labels must include __name__. They are sorted on encode.
	Labels  []Label
	Samples []Sample
}

// Sample is a value at a millisecond timestamp.
type Sample struct {
	Value float64
	TsMs  int64
}

// Encode builds a snappy-compressed WriteRequest.
func Encode(series []Series) []byte {
	var buf []byte
	for _, s := range series {
		ts := encodeSeries(s)
		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendBytes(buf, ts)
	}
	return snappy.Encode(nil, buf)
}

func encodeSeries(s Series) []byte {
	labels := append([]Label(nil), s.Labels...)
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	var b []byte
	for _, l := range labels {
		var lb []byte
		lb = protowire.AppendTag(lb, 1, protowire.BytesType)
		lb = protowire.AppendString(lb, l.Name)
		lb = protowire.AppendTag(lb, 2, protowire.BytesType)
		lb = protowire.AppendString(lb, l.Value)
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, lb)
	}
	for _, smp := range s.Samples {
		var sb []byte
		sb = protowire.AppendTag(sb, 1, protowire.Fixed64Type)
		sb = protowire.AppendFixed64(sb, math.Float64bits(smp.Value))
		sb = protowire.AppendTag(sb, 2, protowire.VarintType)
		sb = protowire.AppendVarint(sb, uint64(smp.TsMs)) //nolint:gosec // int64 -> varint as in prompb
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendBytes(b, sb)
	}
	return b
}

// Writer batches series and posts them asynchronously.
type Writer struct {
	url    string
	client *http.Client
	queue  chan []Series
	// MaxBatchSamples triggers a flush.
	MaxBatchSamples int
	FlushInterval   time.Duration

	Dropped atomic.Int64
	Sent    atomic.Int64
	Failed  atomic.Int64
}

// New creates a writer posting to baseURL + "/api/v1/write".
func New(baseURL string) *Writer {
	return &Writer{
		url:             baseURL + "/api/v1/write",
		client:          &http.Client{Timeout: 15 * time.Second},
		queue:           make(chan []Series, 4096),
		MaxBatchSamples: 20000,
		FlushInterval:   5 * time.Second,
	}
}

// Enqueue adds series without blocking; drops (and counts) when full.
func (w *Writer) Enqueue(s []Series) {
	if len(s) == 0 {
		return
	}
	select {
	case w.queue <- s:
	default:
		w.Dropped.Add(int64(len(s)))
	}
}

// Run flushes batches until ctx is done.
func (w *Writer) Run(ctx context.Context) {
	t := time.NewTicker(w.FlushInterval)
	defer t.Stop()
	var batch []Series
	n := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.post(ctx, batch)
		batch, n = nil, 0
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case s := <-w.queue:
			batch = append(batch, s...)
			for _, x := range s {
				n += len(x.Samples)
			}
			if n >= w.MaxBatchSamples {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (w *Writer) post(ctx context.Context, batch []Series) {
	body := Encode(batch)
	backoff := 500 * time.Millisecond
	for attempt := range 4 {
		err := w.send(ctx, body)
		if err == nil {
			w.Sent.Add(int64(len(batch)))
			return
		}
		if attempt == 3 || ctx.Err() != nil {
			w.Failed.Add(int64(len(batch)))
			slog.WarnContext(ctx, "remote write failed, dropping batch", "series", len(batch), "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (w *Writer) send(ctx context.Context, body []byte) error {
	// Use a detached context on shutdown flush so the last batch can go out.
	sendCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("remotewrite: %w", err)
	}
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("remotewrite: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("remotewrite: status %d", resp.StatusCode)
	}
	return nil
}
