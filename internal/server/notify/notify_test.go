package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookSigned(t *testing.T) {
	got := make(chan *http.Request, 1)
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		got <- r
		w.WriteHeader(204)
	}))
	defer srv.Close()
	err := SendWebhook(context.Background(), srv.Client(), Webhook{Name: "x", URL: srv.URL, Secret: "s3cret"}, Message{Subject: "HostDown", Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	r := <-got
	ts := r.Header.Get("X-Stellwerk-Timestamp")
	if r.Header.Get("X-Stellwerk-Signature") != Signature("s3cret", ts, body) {
		t.Fatal("bad signature")
	}
	if err := SendWebhook(context.Background(), srv.Client(), Webhook{URL: "http://insecure"}, Message{}); err == nil {
		t.Fatal("plain http webhook accepted")
	}
}

func TestEmailRejectsIncomplete(t *testing.T) {
	if err := SendEmail(context.Background(), SMTP{}, Message{}); err == nil {
		t.Fatal("incomplete smtp accepted")
	}
}
