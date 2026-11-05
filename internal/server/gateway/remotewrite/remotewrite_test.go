package remotewrite

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

// decode parses a WriteRequest back (test-only minimal decoder).
func decode(t *testing.T, body []byte) []Series {
	t.Helper()
	raw, err := snappy.Decode(nil, body)
	if err != nil {
		t.Fatal(err)
	}
	var out []Series
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		raw = raw[n:]
		if num != 1 || typ != protowire.BytesType {
			t.Fatalf("unexpected field %d", num)
		}
		ts, n := protowire.ConsumeBytes(raw)
		raw = raw[n:]
		var s Series
		for len(ts) > 0 {
			num, _, n := protowire.ConsumeTag(ts)
			ts = ts[n:]
			b, n := protowire.ConsumeBytes(ts)
			ts = ts[n:]
			switch num {
			case 1:
				var l Label
				for len(b) > 0 {
					f, _, n := protowire.ConsumeTag(b)
					b = b[n:]
					v, n := protowire.ConsumeString(b)
					b = b[n:]
					if f == 1 {
						l.Name = v
					} else {
						l.Value = v
					}
				}
				s.Labels = append(s.Labels, l)
			case 2:
				var smp Sample
				for len(b) > 0 {
					f, typ, n := protowire.ConsumeTag(b)
					b = b[n:]
					if f == 1 && typ == protowire.Fixed64Type {
						v, n := protowire.ConsumeFixed64(b)
						b = b[n:]
						smp.Value = math.Float64frombits(v)
					} else {
						v, n := protowire.ConsumeVarint(b)
						b = b[n:]
						smp.TsMs = int64(v)
					}
				}
				s.Samples = append(s.Samples, smp)
			}
		}
		out = append(out, s)
	}
	return out
}

func TestEncodeRoundTrip(t *testing.T) {
	in := []Series{{Labels: []Label{{"host_id", "h"}, {"__name__", "stellwerk_load1"}}, Samples: []Sample{{1.5, 1000}, {2, 2000}}}}
	got := decode(t, Encode(in))
	if len(got) != 1 || got[0].Labels[0].Name != "__name__" || got[0].Samples[1].Value != 2 || got[0].Samples[0].TsMs != 1000 {
		t.Fatalf("got %+v", got)
	}
}

func TestWriterPosts(t *testing.T) {
	recv := make(chan []Series, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "snappy" || r.URL.Path != "/api/v1/write" {
			w.WriteHeader(400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		recv <- decode(t, b)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	w := New(srv.URL)
	w.FlushInterval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.Enqueue([]Series{{Labels: []Label{{"__name__", "x"}}, Samples: []Sample{{1, 1}}}})
	select {
	case s := <-recv:
		if len(s) != 1 {
			t.Fatalf("got %d series", len(s))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no remote write received")
	}
}
