package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/hubclient"
)

// fakeHubAPI answers like the hub; err makes it unreachable.
type fakeHubAPI struct {
	hosts      hub.HostsResponse
	err        error
	wakes      []string
	onWake     func(name string)
	events     []hub.EventsResponse // answered in order; then drained is called and Events blocks until ctx ends
	polls      []string             // "since boot" per Events call
	drained    func()
	failEvents int                 // the next n Events calls fail
	eventsHook func(call int) bool // when set: call n (from 0) fails if it returns true
	calls      int
	wakeErr    error
}

func (f *fakeHubAPI) Hosts(context.Context) (*hub.HostsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	r := f.hosts
	return &r, nil
}

func (f *fakeHubAPI) Events(ctx context.Context, since uint64, boot string) (*hub.EventsResponse, error) {
	call := f.calls
	f.calls++
	if f.failEvents > 0 || (f.eventsHook != nil && f.eventsHook(call)) {
		if f.failEvents > 0 {
			f.failEvents--
		}
		return nil, errors.New("connection refused")
	}
	f.polls = append(f.polls, strings.TrimSpace(strconv.FormatUint(since, 10)+" "+boot))
	if f.err != nil && f.eventsHook == nil {
		return nil, f.err
	}
	if len(f.events) == 0 {
		if f.drained != nil {
			f.drained()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := f.events[0]
	f.events = f.events[1:]
	return &r, nil
}

func (f *fakeHubAPI) Wake(_ context.Context, name string) error {
	if f.err != nil {
		return f.err
	}
	f.wakes = append(f.wakes, name)
	if f.wakeErr != nil {
		return f.wakeErr
	}
	if f.onWake != nil {
		f.onWake(name)
	}
	return nil
}

const clientHosts = "hub_host = \"mini\"\n"

// withHub gives the harness a fake hub, a cache path and the fake ssh.
func withHub(t *testing.T, h *harness) (*fakeHubAPI, *fakeSSH) {
	t.Helper()
	f := &fakeHubAPI{hosts: hub.HostsResponse{Relay: "mini", Hosts: []hub.HostInfo{
		{Name: "mini", Tailnet: "mini", Tmux: "main", OS: "macos", State: "up", Since: now.Add(-48 * time.Hour), IP: "100.64.0.2"},
		{Name: "fabric-twin", Tailnet: "fabric-twin", User: "krish", OS: "windows", Tmux: "lab", Wakeable: true,
			State: "asleep", Since: now.Add(-3 * time.Hour), IP: "100.64.0.3"},
	}}}
	var gotHost string
	var gotPort int
	h.app.HubClient = func(host string, port int) HubAPI { gotHost, gotPort = host, port; return f }
	t.Cleanup(func() {
		if gotHost != "" && (gotHost != "mini" || gotPort != 7300) {
			t.Errorf("hub client for %s:%d, want mini:7300", gotHost, gotPort)
		}
	})
	ssh := withSSH(t, h)
	h.app.CachePath = filepath.Join(h.app.ControlDir, "hosts.json")
	h.app.Sleep = func(time.Duration) {}
	return f, ssh
}

func TestHubLs(t *testing.T) {
	h := newHarness(t, clientHosts)
	_, _ = withHub(t, h)
	if code := h.run("ls"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	want := []string{
		"NAME STATE OS ADDRESS SINCE",
		"mini up macos 100.64.0.2 2d ago relay",
		"fabric-twin asleep windows 100.64.0.3 3h ago wakeable",
	}
	for i, w := range want {
		if i >= len(lines) || strings.Join(strings.Fields(lines[i]), " ") != w {
			t.Errorf("line %d = %q, want %q\n%s", i, lineAt(lines, i), w, h.out)
		}
	}
	// the answer is cached for direct mode later
	if _, _, err := hubclient.LoadCache(h.app.CachePath); err != nil {
		t.Errorf("no cache written: %v", err)
	}
}

func TestHubWake(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, ssh := withHub(t, h)
	f.onWake = func(name string) { h.tn.set(name, true) }
	if code := h.run("wake", "fabric-twin"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if strings.Join(f.wakes, ",") != "fabric-twin" || len(ssh.calls) != 0 {
		t.Errorf("hub wakes %v, ssh calls %v (want the hub, no relay ssh)", f.wakes, ssh.calls)
	}
	if !strings.Contains(h.errOut.String(), "via the hub") || !strings.Contains(h.errOut.String(), "fabric-twin is up") {
		t.Errorf("stderr %q", h.errOut)
	}

	// auto-wake through the hub, then ssh with the user and tmux the hub's list gives
	h.tn.set("fabric-twin", false)
	f.wakes = nil
	if code := h.run("fabric-twin", "uptime"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if len(f.wakes) != 1 || len(ssh.calls) != 1 || !strings.HasSuffix(ssh.last(), "-T -- krish@fabric-twin uptime") {
		t.Errorf("wakes %v, ssh %v", f.wakes, ssh.calls)
	}
	h.out.Reset()
	if code := h.run("fabric-twin"); code != 0 || !strings.Contains(ssh.last(), "-t -- krish@fabric-twin tmux attach -t 'lab'") {
		t.Errorf("shell: exit %d, %s", code, ssh.last())
	}

	// the hub cannot wake a host it has no mac for: the reason says so
	h.tn.set("mini", false)
	h.errOut.Reset()
	h.run("mini", "uptime")
	if !strings.Contains(h.errOut.String(), "the hub has no mac for it") {
		t.Errorf("stderr %q", h.errOut)
	}
}

func TestHubFallback(t *testing.T) {
	// a good answer first, so there is a cache
	h := newHarness(t, clientHosts)
	f, ssh := withHub(t, h)
	if code := h.run("ls"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	cacheTime := time.Now().Add(-5 * time.Minute)
	os.Chtimes(h.app.CachePath, cacheTime, cacheTime)

	// the hub goes away: one notice, then direct mode from the cache
	f.err = errors.New("dial tcp 100.64.0.2:7300: connect: connection refused")
	h.out.Reset()
	h.errOut.Reset()
	if code := h.run("ls"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if n := strings.Count(h.errOut.String(), "\n"); n != 1 || !strings.Contains(h.errOut.String(), "hub mini unreachable") ||
		!strings.Contains(h.errOut.String(), "cached 5m ago") {
		t.Errorf("notice %q", h.errOut)
	}
	if !hasField(h.out.String(), "fabric-twin asleep windows") {
		t.Errorf("direct-mode ls from the cache:\n%s", h.out)
	}
	if code := h.run("mini", "uptime"); code != 0 || !strings.HasSuffix(ssh.last(), "-T -- mini uptime") {
		t.Errorf("command from the cache: exit %d, %s", code, ssh.last())
	}

	// no cache and no local hosts: a clear error, not an empty success
	os.Remove(h.app.CachePath)
	h.errOut.Reset()
	if code := h.run("fabric-twin", "uptime"); code == 0 || !strings.Contains(h.errOut.String(), "unknown") {
		t.Errorf("nothing to fall back to: exit %d, %q", code, h.errOut)
	}

	// local hosts with a mac still wake through the relay when the hub is down
	h2 := newHarness(t, clientHosts+"relay = \"mini\"\n[[host]]\nname = \"mini\"\n[[host]]\nname = \"fabric-twin\"\nmac = \"aa:bb:cc:dd:ee:01\"\n")
	f2, ssh2 := withHub(t, h2)
	f2.err = errors.New("hub down")
	h2.app.Exec = func(ctx context.Context, argv []string) (int, error) {
		if strings.Contains(strings.Join(argv, " "), "labctl wol") {
			h2.tn.set("fabric-twin", true)
		}
		return ssh2.exec(ctx, argv)
	}
	if code := h2.run("wake", "fabric-twin"); code != 0 || !strings.Contains(ssh2.last(), "labctl wol 'aa:bb:cc:dd:ee:01'") {
		t.Errorf("relay fallback: exit %d, %s\n%s", code, ssh2.last(), h2.errOut)
	}
}

func hasField(out, fields string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.Join(strings.Fields(line), " "), fields) {
			return true
		}
	}
	return false
}

func ev(seq uint64, host, from, to string) hub.Event {
	return hub.Event{Seq: seq, Time: now.Add(time.Duration(seq) * time.Second), Host: host, From: from, To: to}
}

// runWatch runs labctl watch until the fake hub has no more answers, then stops it like Ctrl-C would.
func runWatch(t *testing.T, h *harness, f *fakeHubAPI) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.drained = cancel
	done := make(chan int, 1)
	go func() { done <- h.app.Run(ctx, []string{"watch"}) }()
	select {
	case code := <-done:
		return code
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("watch did not stop")
		return -1
	}
}

func TestWatch(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, _ := withHub(t, h)
	var first []hub.Event
	for i := uint64(1); i <= 12; i++ {
		first = append(first, ev(i, "fabric-twin", "up", "asleep"))
	}
	f.events = []hub.EventsResponse{
		{Events: first, Last: 12, Boot: "b1"},
		{Events: []hub.Event{ev(13, "fabric-twin", "asleep", "up")}, Last: 13, Boot: "b1"},
		{Events: []hub.Event{ev(1, "mini", "", "up")}, Last: 1, Boot: "b2"}, // the hub restarted
	}
	if code := runWatch(t, h, f); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	if len(lines) != 12 { // the last 10 of the history, then the live one, then the one after the restart
		t.Fatalf("%d lines:\n%s", len(lines), h.out)
	}
	if !strings.Contains(lines[0], "fabric-twin") || !strings.Contains(lines[10], "asleep -> up") || !strings.Contains(lines[11], "mini") || !strings.Contains(lines[11], "(start) -> up") {
		t.Errorf("output:\n%s", h.out)
	}
	if strings.Join(f.polls, "|") != "0|12 b1|13 b1|1 b2" {
		t.Errorf("polls %q", f.polls)
	}
	if !strings.Contains(h.errOut.String(), "hub restarted") {
		t.Errorf("stderr %q", h.errOut)
	}
}

func TestWatchRetries(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, _ := withHub(t, h)
	f.err = errors.New("hub down: GET /v1/hosts fails") // watch must not need the host list
	f.eventsHook = func(call int) bool { return call <= 1 || call == 3 || call == 4 } // outages: calls 0-1, 3-4
	f.events = []hub.EventsResponse{
		{Events: []hub.Event{ev(1, "mini", "", "up")}, Last: 1, Boot: "b1"},
		{Events: []hub.Event{ev(2, "korg", "up", "asleep")}, Last: 2, Boot: "b1"},
	}
	runWatch(t, h, f)
	if n := strings.Count(h.errOut.String(), "retrying"); n != 2 {
		t.Errorf("two outages must be reported once each, got %d:\n%s", n, h.errOut)
	}
	if n := strings.Count(h.errOut.String(), "hub back"); n != 2 {
		t.Errorf("two recoveries, got %d:\n%s", n, h.errOut)
	}
	if strings.Contains(h.errOut.String(), "direct mode") {
		t.Errorf("watch went through direct mode:\n%s", h.errOut)
	}
	if !strings.Contains(h.out.String(), "mini") || !strings.Contains(h.out.String(), "korg") {
		t.Errorf("events:\n%s", h.out)
	}
}

func TestWatchNeedsHub(t *testing.T) {
	h := newHarness(t, hostsFile)
	if code := h.run("watch"); code == 0 || !strings.Contains(h.errOut.String(), "hub_host") {
		t.Errorf("exit %d, %q", code, h.errOut)
	}
}

// T3: event text comes from the hub; escape sequences must not reach the terminal
func TestWatchStripsControlChars(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, _ := withHub(t, h)
	f.events = []hub.EventsResponse{{Events: []hub.Event{ev(1, "evil\x1b[2J", "up\x07", "\x1b]0;pwned\x07")}, Last: 1, Boot: "b"}}
	runWatch(t, h, f)
	if strings.ContainsAny(h.out.String()+h.errOut.String(), "\x1b\x07") {
		t.Errorf("control characters reached the terminal: %q", h.out)
	}
}

// security L3: in hub mode a host that is also in the local file keeps the local tailnet, user and tmux: a
// compromised hub cannot point fabric-twin at another machine or log in as another user
func TestHubModeLocalPins(t *testing.T) {
	h := newHarness(t, clientHosts+"[[host]]\nname = \"fabric-twin\"\nuser = \"krish\"\n")
	f, ssh := withHub(t, h)
	f.hosts.Hosts[1].Tailnet, f.hosts.Hosts[1].User = "mini", "root"
	f.hosts.Hosts = append(f.hosts.Hosts, hub.HostInfo{Name: "alias", Tailnet: "fabric-twin", User: "root", Tmux: "main"})
	h.tn.set("fabric-twin", true)
	if code := h.run("fabric-twin", "id"); code != 0 || !strings.HasSuffix(ssh.last(), "-T -- krish@fabric-twin id") {
		t.Errorf("exit %d: %s", code, ssh.last())
	}
	if code := h.run("alias", "id"); code == 0 {
		t.Errorf("a hub host reusing a local host's tailnet name was kept: %s", ssh.last())
	}
	h.tn.set("fabric-twin", false)
	f.onWake = func(name string) { h.tn.set(name, true) }
	if code := h.run("wake", "fabric-twin"); code != 0 || len(f.wakes) != 1 {
		t.Errorf("a pinned host is still woken through the hub: exit %d, wakes %v, %s", code, f.wakes, h.errOut)
	}
}

// security L2: in direct mode a cached host cannot shadow a local one through its tailnet name
func TestFallbackLocalWins(t *testing.T) {
	h := newHarness(t, clientHosts+"relay = \"mini\"\n[[host]]\nname = \"mini\"\n[[host]]\nname = \"nas\"\nmac = \"aa:bb:cc:dd:ee:07\"\n")
	f, ssh := withHub(t, h)
	f.hosts = hub.HostsResponse{Hosts: []hub.HostInfo{
		{Name: "x", Tailnet: "nas", User: "root", Tmux: "main"},
		{Name: "korg", Tailnet: "korg", Tmux: "main"},
	}}
	h.run("ls") // caches the hub's answer
	f.err = errors.New("hub down")
	h.errOut.Reset()
	if code := h.run("nas", "id"); code != 0 || !strings.HasSuffix(ssh.last(), "-T -- nas id") {
		t.Errorf("exit %d: %s %s", code, ssh.last(), h.errOut)
	}
	if code := h.run("korg", "id"); code != 0 || !strings.HasSuffix(ssh.last(), "-T -- korg id") {
		t.Errorf("a cached host that does not collide is still usable: exit %d, %s", code, ssh.last())
	}
}
