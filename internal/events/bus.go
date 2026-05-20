// Package events is a minimal in-process event bus. Replace with Kafka or
// NATS by implementing the Publisher interface against your broker SDK.
package events

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Event is the canonical envelope written to the bus.
type Event struct {
	Time     time.Time         `json:"time"`
	Source   string            `json:"source"`
	Kind     string            `json:"kind"`
	Severity string            `json:"severity"`
	Actor    string            `json:"actor,omitempty"`
	Target   string            `json:"target,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// Publisher is the small interface every service depends on.
type Publisher interface {
	Publish(ev Event)
	Subscribe() <-chan Event
}

// Memory is a fan-out in-memory implementation good for single-host dev.
type Memory struct {
	mu   sync.Mutex
	subs []chan Event
}

// New returns a new in-memory Publisher.
func New() *Memory { return &Memory{} }

// Publish ships ev to every subscriber non-blockingly.
func (m *Memory) Publish(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.subs {
		select {
		case s <- ev:
		default:
			// drop on slow consumer — production code should report this
		}
	}
	// also log a JSON line for visibility in dev
	if b, err := json.Marshal(ev); err == nil {
		log.Printf("EVT %s", b)
	}
}

// Subscribe returns a buffered channel that will receive every future event.
func (m *Memory) Subscribe() <-chan Event {
	ch := make(chan Event, 256)
	m.mu.Lock()
	m.subs = append(m.subs, ch)
	m.mu.Unlock()
	return ch
}
