package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
)

// fakeHub is an httptest server standing in for the hub; the client reaches it through a dialer that ignores the
// address (the Host header still says mini:7300, as on the real tailnet).
type fakeHub struct {
	srv      *httptest.Server
	hosts    hub.HostsResponse
	wakeCode int
	got      []*http.Request
}

func newFakeHub(t *testing.T) (*fakeHub, *Client) {
	t.Helper()
	f := &fakeHub{wakeCode: http.StatusAccepted, hosts: hub.HostsResponse{Relay: "mini", Hosts: []hub.HostInfo{
		{Name: "mini", Tailnet: "mini", Tmux: "main", State: "up", IP: "100.64.0.10"},
		{Name: "korg", Tailnet: "korg", User: "krish", OS: "windows", Tmux: "lab", Wakeable: true, State: "asleep"},
	}}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.got = append(f.got, r)
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/hosts":
			json.NewEncoder(w).Encode(f.hosts)
		case r.Method == "GET" && r.URL.Path == "/v1/events":
			json.NewEncoder(w).Encode(hub.EventsResponse{Events: []hub.Event{{Seq: 7, Host: "korg", From: "up", To: "asleep"}}, Last: 7, Boot: "b1"})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/wake/"):
			w.WriteHeader(f.wakeCode)
			json.NewEncoder(w).Encode(map[string]string{"result": "woken less than 10 s ago"})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	addr := f.srv.Listener.Addr().String()
	c := New("mini", 7300, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})
	return f, c
}

func TestClient(t *testing.T) {
	f, c := newFakeHub(t)
	ctx := context.Background()
	hosts, err := c.Hosts(ctx)
	if err != nil || len(hosts.Hosts) != 2 {
		t.Fatalf("Hosts: %+v %v", hosts, err)
	}
	if f.got[0].Host != "mini:7300" {
		t.Errorf("Host header %q, want the hub's MagicDNS name", f.got[0].Host)
	}
	ev, err := c.Events(ctx, 6, "b1")
	if err != nil || ev.Last != 7 || f.got[1].URL.RawQuery != "boot=b1&since=6" {
		t.Errorf("Events: %+v %v, query %q", ev, err, f.got[1].URL.RawQuery)
	}
	if err := c.Wake(ctx, "korg"); err != nil {
		t.Errorf("Wake: %v", err)
	}
	if w := f.got[2]; w.URL.Path != "/v1/wake/korg" || w.Header.Get("X-Labctl") != "1" {
		t.Errorf("wake request %s %v", w.URL.Path, w.Header)
	}
	f.wakeCode = http.StatusTooManyRequests
	if err := c.Wake(ctx, "korg"); err == nil || !strings.Contains(err.Error(), "10 s ago") {
		t.Errorf("429: %v", err)
	}
	f.wakeCode = http.StatusForbidden
	if err := c.Wake(ctx, "korg"); err == nil || !strings.Contains(err.Error(), "allowed login") {
		t.Errorf("403: %v", err)
	}
	if err := c.Wake(ctx, "a/../b"); err == nil {
		t.Error("a host name with a slash was sent")
	}
}

// T1: a hub answer or a cache file with unsafe names is refused whole, never half-used.
func TestRejectsUnsafeHostList(t *testing.T) {
	f, c := newFakeHub(t)
	if inv, err := Inventory(&f.hosts); err != nil || len(inv) != 2 || !inv[1].HubWakeable || inv[1].User != "krish" || inv[1].MAC != "" {
		t.Fatalf("valid list: %+v %v", inv, err)
	}
	for _, bad := range []hub.HostInfo{
		{Name: "-oProxyCommand=touch /tmp/x", Tailnet: "a"},
		{Name: "a", Tailnet: "-oX"},
		{Name: "a", Tailnet: "a", User: "x@evil"},
		{Name: "a", Tailnet: "a", Tmux: "x;reboot"},
	} {
		f.hosts.Hosts = append(f.hosts.Hosts[:2:2], bad)
		if _, err := c.Hosts(context.Background()); err == nil {
			t.Errorf("hub answer with %+v accepted", bad)
		}
	}
	// the same rule on a cache file someone edited
	path := filepath.Join(t.TempDir(), "hosts.json")
	data, _ := json.Marshal(hub.HostsResponse{Hosts: []hub.HostInfo{{Name: "-oProxyCommand=x", Tailnet: "a"}}})
	os.WriteFile(path, data, 0o600)
	if _, _, err := LoadCache(path); err == nil {
		t.Error("unsafe cache accepted")
	}
}

func TestCache(t *testing.T) {
	f, _ := newFakeHub(t)
	path := filepath.Join(t.TempDir(), "cache", "hosts.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveCache(path, &f.hosts); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("cache mode %v", fi.Mode().Perm())
	}
	got, at, err := LoadCache(path)
	if err != nil || len(got.Hosts) != 2 || time.Since(at) > time.Minute {
		t.Errorf("LoadCache: %+v %v %v", got, at, err)
	}
	if _, _, err := LoadCache(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing cache loaded")
	}
}

// T2: the hub name must resolve to Tailscale addresses only; a LAN or public answer is never dialed.
func TestHubAddress(t *testing.T) {
	var dialed []string
	d := Dialer{
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "mini":
				return []netip.Addr{netip.MustParseAddr("192.168.1.9"), netip.MustParseAddr("100.64.0.10")}, nil
			case "impostor":
				return []netip.Addr{netip.MustParseAddr("192.168.1.66"), netip.MustParseAddr("8.8.8.8")}, nil
			}
			return nil, errors.New("no such host")
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, errors.New("test: not connecting")
		},
	}
	ctx := context.Background()
	d.DialContext(ctx, "tcp", "mini:7300")
	if len(dialed) != 1 || dialed[0] != "100.64.0.10:7300" {
		t.Errorf("mini dialed %v, want only its Tailscale address", dialed)
	}
	dialed = nil
	for _, addr := range []string{"impostor:7300", "192.168.1.9:7300", "8.8.8.8:7300", "nowhere:7300"} {
		if _, err := d.DialContext(ctx, "tcp", addr); err == nil || len(dialed) != 0 {
			t.Errorf("%s: err %v, dialed %v", addr, err, dialed)
		}
	}
	d.DialContext(ctx, "tcp", "[fd7a:115c:a1e0::10]:7300")
	if len(dialed) != 1 {
		t.Errorf("a Tailscale IPv6 literal was not dialed: %v", dialed)
	}
}
