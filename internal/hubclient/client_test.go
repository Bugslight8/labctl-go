package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/tailnet"
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

// T2 (security round 1, M1): the hub's address comes from this machine's Tailscale, never from DNS. Only a peer of
// this tailnet with that MagicDNS name is dialed, at its own Tailscale address; with Tailscale down, nothing is.
func TestHubAddress(t *testing.T) {
	var dialed []string
	status := &tailnet.Status{Suffix: "tail0000.ts.net", Peers: []tailnet.Peer{
		{Name: "mini", DNSName: "mini.other.ts.net", IP: "100.64.9.9"}, // shared in from another tailnet
		{Name: "mini", DNSName: "mini.tail0000.ts.net", IP: "100.64.0.10"},
		{Name: "shared", DNSName: "shared.other.ts.net", IP: "100.64.9.8"},
	}}
	var statusErr error
	d := Dialer{
		Status: func(context.Context) (*tailnet.Status, error) { return status, statusErr },
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, errors.New("test: not connecting")
		},
	}
	ctx := context.Background()
	for _, addr := range []string{"mini:7300", "mini.tail0000.ts.net:7300", "100.64.0.10:7300"} {
		dialed = nil
		d.DialContext(ctx, "tcp", addr)
		if len(dialed) != 1 || dialed[0] != "100.64.0.10:7300" {
			t.Errorf("%s dialed %v, want only this tailnet's mini", addr, dialed)
		}
	}
	dialed = nil
	for _, addr := range []string{
		"shared:7300",            // only a shared-in node has that name
		"mini.other.ts.net:7300", // the shared-in node by full name
		"100.127.1.1:7300",       // a carrier-range address that is no peer (a café's DNS answer)
		"100.64.9.9:7300",        // the shared-in node's address
		"192.168.1.9:7300", "nowhere:7300",
	} {
		if _, err := d.DialContext(ctx, "tcp", addr); err == nil || len(dialed) != 0 {
			t.Errorf("%s: err %v, dialed %v", addr, err, dialed)
		}
	}
	statusErr = errors.New("tailscale is Stopped on this machine")
	if _, err := d.DialContext(ctx, "tcp", "mini:7300"); err == nil || len(dialed) != 0 {
		t.Errorf("Tailscale down: err %v, dialed %v", err, dialed)
	}
}

// M2: the hub's error text reaches the terminal only without control characters, and short
func TestErrorTextIsPrintable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"result": "\x1b]0;owned\a\x1b[2J" + strings.Repeat("x", 5000)})
	}))
	defer srv.Close()
	c := New("mini", 7300, func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, srv.Listener.Addr().String())
	})
	_, err := c.Hosts(context.Background())
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\a") || len(err.Error()) > 300 {
		t.Errorf("error %q", err)
	}
}

// L1: a redirect is never followed (it would carry X-Labctl to wherever an impostor points)
func TestNoRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/wake/korg", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New("mini", 7300, func(ctx context.Context, n, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "mini:") {
			addr = srv.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, n, addr)
	})
	if err := c.Wake(context.Background(), "korg"); err == nil || hit {
		t.Errorf("redirect followed: err %v, target hit %v", err, hit)
	}
}

// review R1: an answer without its lists is an error, never an empty list (which would then be cached)
func TestMissingFields(t *testing.T) {
	body := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/wake/") {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	c := New("mini", 7300, func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, srv.Listener.Addr().String())
	})
	ctx := context.Background()
	body = `{"relay": "mini", "items": [{"name": "korg"}]}`
	if _, err := c.Hosts(ctx); err == nil {
		t.Error("hosts answer without hosts accepted")
	}
	body = `{"relay": "mini", "hosts": []}`
	if r, err := c.Hosts(ctx); err != nil || len(r.Hosts) != 0 {
		t.Errorf("an empty list is fine: %v", err)
	}
	for _, b := range []string{`{"last": 3}`, `{"events": [], "last": 3}`, `{"boot": "b", "last": 3}`} {
		body = b
		if _, err := c.Events(ctx, 0, ""); err == nil {
			t.Errorf("events answer %s accepted", b)
		}
	}
	if err := c.Wake(ctx, "korg"); !errors.Is(err, ErrRecentlyWoken) {
		t.Errorf("429 = %v, want ErrRecentlyWoken", err)
	}
}
