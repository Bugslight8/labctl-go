// Package hub is `labctl hub`: the always-on service on the relay that watches every host, keeps the history of
// state changes, serves both to the owner's devices over the tailnet, and wakes hosts.
package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

// State is what the hub knows about a host.
type State string

const (
	Up           State = "up"             // tailnet online and port 22 answers
	Unreachable  State = "unreachable"    // tailnet says online but port 22 is silent: often asleep with a stale entry
	Asleep       State = "asleep"         // tailnet offline
	NotOnTailnet State = "not-on-tailnet" // in the hosts file, unknown to the tailnet
)

const (
	maxEvents    = 1000
	probeTimeout = 2 * time.Second
)

// HostState is one host as the hub sees it.
type HostState struct {
	Name     string
	State    State
	Since    time.Time // when State last changed
	OS, IP   string
	LastSeen time.Time // from the tailnet, zero while online
}

// Event is one state change. Seq grows by one per event, so a client asks for "everything after N".
type Event struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	Host string    `json:"host"`
	From string    `json:"from"` // "" on the hub's first poll
	To   string    `json:"to"`
}

// Monitor polls the tailnet and the hosts' ssh ports and records every change.
type Monitor struct {
	inv    *inventory.Inventory
	status func(context.Context) (*tailnet.Status, error)
	dial   func(ctx context.Context, addr string) error
	now    func() time.Time

	// Boot is random per start: event numbers restart at 1 with the hub, so a client that sees a new Boot starts
	// over from since=0 instead of skipping events.
	Boot string

	mu      sync.Mutex
	hosts   map[string]HostState
	events  []Event
	seq     uint64
	changed chan struct{} // closed and replaced on every new event: wakes all waiters
}

// NewMonitor watches inv's hosts. dial probes host:port and returns nil when something answers.
func NewMonitor(inv *inventory.Inventory, status func(context.Context) (*tailnet.Status, error),
	dial func(ctx context.Context, addr string) error, now func() time.Time) *Monitor {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Monitor{inv: inv, status: status, dial: dial, now: now, Boot: hex.EncodeToString(b),
		hosts: map[string]HostState{}, changed: make(chan struct{})}
}

// DialTCP is the real port probe.
func DialTCP(ctx context.Context, addr string) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Poll runs one round: tailnet status, then a port-22 probe of every host the tailnet calls online, in parallel.
// A failed status query changes nothing and is returned.
func (m *Monitor) Poll(ctx context.Context) error {
	st, err := m.status(ctx)
	if err != nil {
		return err
	}
	type result struct {
		h     inventory.Host
		p     tailnet.Peer
		state State
	}
	results := make([]result, len(m.inv.Hosts))
	var wg sync.WaitGroup
	for i, h := range m.inv.Hosts {
		if isSelf(st.Self, h.Tailnet) { // the machine the hub runs on: tailscale lists it as Self, not as a peer
			results[i] = result{h: h, p: st.Self, state: Up}
			continue
		}
		p, ok := st.Lookup(h.Tailnet)
		results[i] = result{h: h, p: p, state: NotOnTailnet}
		switch {
		case !ok:
		case !p.Online:
			results[i].state = Asleep
		default:
			wg.Add(1)
			go func(i int, ip string) {
				defer wg.Done()
				pctx, cancel := context.WithTimeout(ctx, probeTimeout)
				defer cancel()
				results[i].state = Unreachable
				if ip != "" && m.dial(pctx, net.JoinHostPort(ip, "22")) == nil {
					results[i].state = Up
				}
			}(i, p.IP)
		}
	}
	wg.Wait()
	for _, r := range results {
		m.update(r.h.Name, r.state, r.p)
	}
	return nil
}

// Run polls every interval until ctx ends; errors go to logf.
func (m *Monitor) Run(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	for {
		if err := m.Poll(ctx); err != nil && ctx.Err() == nil {
			logf("poll: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func isSelf(self tailnet.Peer, name string) bool {
	full := strings.TrimSuffix(name, ".")
	return self.Name != "" && (strings.EqualFold(self.Name, full) || strings.EqualFold(self.DNSName, full))
}

func (m *Monitor) update(name string, s State, p tailnet.Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, seen := m.hosts[name]
	h.Name, h.OS, h.IP, h.LastSeen = name, p.OS, p.IP, p.LastSeen
	m.hosts[name] = h
	if !seen || h.State != s {
		m.recordLocked(name, s)
	}
}

func (m *Monitor) recordLocked(name string, s State) {
	h := m.hosts[name]
	now := m.now()
	m.seq++
	m.events = append(m.events, Event{Seq: m.seq, Time: now, Host: name, From: string(h.State), To: string(s)})
	if len(m.events) > maxEvents {
		m.events = append([]Event(nil), m.events[len(m.events)-maxEvents:]...)
	}
	h.Name, h.State, h.Since = name, s, now
	m.hosts[name] = h
	close(m.changed)
	m.changed = make(chan struct{})
}

// Hosts returns every host in hosts-file order.
func (m *Monitor) Hosts() []HostState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HostState, 0, len(m.inv.Hosts))
	for _, h := range m.inv.Hosts {
		if s, ok := m.hosts[h.Name]; ok {
			out = append(out, s)
		}
	}
	return out
}

// eventsLocked returns the retained events with Seq > since. When since is older than the oldest retained event,
// the first returned Seq is greater than since+1, so the client can see that it missed some.
func (m *Monitor) eventsLocked(since uint64) []Event {
	var out []Event
	for _, e := range m.events {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	return out
}

// Wait returns the events after since and the newest Seq, read under one lock so that asking since=last next time
// never skips an event. It blocks until there is at least one event or ctx ends (then it returns none).
// A since beyond the newest Seq comes from before a hub restart: it counts as 0.
func (m *Monitor) Wait(ctx context.Context, since uint64) ([]Event, uint64) {
	for {
		m.mu.Lock()
		if since > m.seq {
			since = 0
		}
		ev, last, ch := m.eventsLocked(since), m.seq, m.changed
		m.mu.Unlock()
		if len(ev) > 0 {
			return ev, last
		}
		select {
		case <-ctx.Done():
			return nil, last
		case <-ch:
		}
	}
}
