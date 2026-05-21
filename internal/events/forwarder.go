package events

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Forwarder wraps a local Publisher and ships every published event to a
// remote audit-service over HTTP. Publish is non-blocking — events go to a
// buffered channel and a background goroutine POSTs them.
//
// This is what makes per-service in-process buses (auth, ssh-proxy, tacacs,
// rdp-proxy) actually land in the central audit_events table.
type Forwarder struct {
	inner    Publisher
	auditURL string
	client   *http.Client
	ch       chan Event
	once     sync.Once
	stop     chan struct{}
}

// NewForwarder returns a Publisher that publishes locally AND forwards to
// auditURL ("/events" path appended automatically). When auditURL is empty,
// the underlying publisher is returned unchanged.
func NewForwarder(inner Publisher, auditURL string) Publisher {
	if auditURL == "" {
		return inner
	}
	f := &Forwarder{
		inner:    inner,
		auditURL: auditURL + "/events",
		client:   &http.Client{Timeout: 5 * time.Second},
		ch:       make(chan Event, 1024),
		stop:     make(chan struct{}),
	}
	go f.run()
	return f
}

// Publish enqueues the event locally and remotely.
func (f *Forwarder) Publish(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	f.inner.Publish(ev)
	select {
	case f.ch <- ev:
	default:
		log.Printf("event forwarder: dropping event (queue full): %s/%s", ev.Source, ev.Kind)
	}
}

// Subscribe delegates to the inner publisher so local consumers still work.
func (f *Forwarder) Subscribe() <-chan Event { return f.inner.Subscribe() }

// Close stops the background shipper.
func (f *Forwarder) Close() {
	f.once.Do(func() { close(f.stop) })
}

func (f *Forwarder) run() {
	for {
		select {
		case <-f.stop:
			return
		case ev := <-f.ch:
			f.send(ev)
		}
	}
}

func (f *Forwarder) send(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.auditURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		log.Printf("event forwarder: post %s/%s: %v", ev.Source, ev.Kind, err)
		return
	}
	resp.Body.Close()
}
