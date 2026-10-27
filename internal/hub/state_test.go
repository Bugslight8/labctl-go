package hub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const hostsFile = `
relay = "mini"

[hub]
allow = ["owner@example.com"]

[[host]]
name = "mini"

[[host]]
name = "fabric-twin"
mac = "aa:bb:cc:dd:ee:01"

[[host]]
name = "nas"
`

// fakeLab is a tailnet plus a set of hosts whose port 22 answers; the test changes both between polls.
type fakeLab struct {
	mu        sync.Mutex
	peers     []tailnet.Peer
	sshOK     map[string]bool // IP -> port 22 answers
	statusErr error
	clock     time.Time
}

func newFakeLab() *fakeLab {
	return &fakeLab{
		peers: []tailnet.Peer{
			{Name: "mini", DNSName: "mini.tail0000.ts.net", Online: true, IP: "100.64.0.2", OS: "macos"},
			{Name: "fabric-twin", DNSName: "fabric-twin.tail0000.ts.net", Online: true, IP: "100.64.0.3", OS: "windows"},
		},
		sshOK: map[string]bool{"100.64.0.2": true},
		clock: t0,
	}
}

func (f *fakeLab) status(context.Context) (*tailnet.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &tailnet.Status{Suffix: "tail0000.ts.net", Peers: append([]tailnet.Peer(nil), f.peers...)}, nil
}

func (f *fakeLab) dial(_ context.Context, addr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ip, ok := range f.sshOK {
		if ok && addr == ip+":22" {
			return nil
		}
	}
	return errors.New("connection refused")
}

func (f *fakeLab) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock }

func (f *fakeLab) advance(d time.Duration) { f.mu.Lock(); f.clock = f.clock.Add(d); f.mu.Unlock() }

func (f *fakeLab) setOnline(name string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.peers {
		if f.peers[i].Name == name {
			f.peers[i].Online = on
		}
	}
}

func newMonitor(t *testing.T) (*Monitor, *fakeLab) {
	t.Helper()
	inv, err := inventory.Parse([]byte(hostsFile))
	if err != nil {
		t.Fatal(err)
	}
	lab := newFakeLab()
	return NewMonitor(inv, lab.status, lab.dial, lab.now), lab
}

func states(m *Monitor) map[string]State {
	out := map[string]State{}
	for _, h := range m.Hosts() {
		out[h.Name] = h.State
	}
	return out
}

func TestPoll(t *testing.T) {
	m, lab := newMonitor(t)
	if err := m.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[string]State{"mini": Up, "fabric-twin": Unreachable, "nas": NotOnTailnet}
	for name, s := range want {
		if got := states(m)[name]; got != s {
			t.Errorf("%s = %q, want %q", name, got, s)
		}
	}
	// first poll: one event per host, from "" (the hub's baseline)
	if ev := m.Events(0); len(ev) != 3 || ev[0].From != "" {
		t.Fatalf("baseline events %+v", ev)
	}

	// nothing changed: no new events, Since stays
	lab.advance(5 * time.Second)
	m.Poll(context.Background())
	if ev := m.Events(3); len(ev) != 0 {
		t.Errorf("unchanged poll made events %+v", ev)
	}

	// fabric-twin sleeps for real; port 22 starts answering on... nothing; then it wakes
	lab.advance(5 * time.Second)
	lab.setOnline("fabric-twin", false)
	m.Poll(context.Background())
	ev := m.Events(3)
	if len(ev) != 1 || ev[0].Host != "fabric-twin" || ev[0].From != string(Unreachable) || ev[0].To != string(Asleep) || ev[0].Seq != 4 {
		t.Fatalf("sleep event %+v", ev)
	}
	for _, h := range m.Hosts() {
		if h.Name == "fabric-twin" && !h.Since.Equal(t0.Add(10*time.Second)) {
			t.Errorf("since = %v", h.Since)
		}
		if h.Name == "mini" && !h.Since.Equal(t0) {
			t.Errorf("mini since moved: %v", h.Since)
		}
	}
	lab.setOnline("fabric-twin", true)
	lab.sshOK["100.64.0.3"] = true
	m.Poll(context.Background())
	if states(m)["fabric-twin"] != Up {
		t.Errorf("woken host = %q", states(m)["fabric-twin"])
	}

	// tailscale failing: the error comes back and the states stay as they were
	lab.statusErr = errors.New("tailscaled not running")
	if err := m.Poll(context.Background()); err == nil {
		t.Error("status error swallowed")
	}
	if states(m)["mini"] != Up || len(m.Events(5)) != 0 {
		t.Error("a failed poll changed state")
	}
}

func TestEvents(t *testing.T) {
	m, _ := newMonitor(t)
	for i := 0; i < maxEvents+50; i++ {
		m.record("h", State("s"+string(rune('a'+i%2))))
	}
	ev := m.Events(0)
	if len(ev) != maxEvents || ev[len(ev)-1].Seq != uint64(maxEvents+50) {
		t.Fatalf("ring holds %d, last seq %d", len(ev), ev[len(ev)-1].Seq)
	}
	if ev[0].Seq != 51 {
		t.Errorf("oldest kept seq %d, want 51", ev[0].Seq)
	}

	// Wait returns at once when there is news, blocks until a new event otherwise, and gives up with ctx
	last := ev[len(ev)-1].Seq
	if got := m.Wait(context.Background(), last-1); len(got) != 1 {
		t.Errorf("Wait with news = %d events", len(got))
	}
	done := make(chan []Event)
	go func() { done <- m.Wait(context.Background(), last) }()
	time.Sleep(20 * time.Millisecond)
	m.record("h", "new")
	select {
	case got := <-done:
		if len(got) != 1 || got[0].To != "new" {
			t.Errorf("woken Wait = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not wake on a new event")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if got := m.Wait(ctx, last+1); len(got) != 0 {
		t.Errorf("Wait past ctx = %+v", got)
	}
}
