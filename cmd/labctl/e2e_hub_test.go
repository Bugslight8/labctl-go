package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

// syncBuffer is a bytes.Buffer that watch (in a goroutine) and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func (s *syncBuffer) Reset()         { s.mu.Lock(); defer s.mu.Unlock(); s.b.Reset() }

// asOwner makes every accepted connection come from the owner's MacBook (100.64.0.1), as on the real tailnet.
type asOwner struct{ net.Listener }

type ownerConn struct{ net.Conn }

func (ownerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 41000}
}

func (l asOwner) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return ownerConn{c}, nil
}

// lab is the fake home network both sides see: the hub (mini, tailscale's Self on its side) and fabric-twin.
type lab struct {
	mu     sync.Mutex
	ftUp   bool
	sent   []string
	hubIPs []string
}

func (l *lab) status(self string) func(context.Context) (*tailnet.Status, error) {
	return func(context.Context) (*tailnet.Status, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		mini := tailnet.Peer{Name: "mini", DNSName: "mini.tail0000.ts.net", Online: true, IP: "100.64.0.10", OS: "macos"}
		ft := tailnet.Peer{Name: "fabric-twin", DNSName: "fabric-twin.tail0000.ts.net", Online: l.ftUp, IP: "100.64.0.3", OS: "windows",
			LastSeen: time.Now().Add(-time.Hour)}
		mbp := tailnet.Peer{Name: "macbook-pro", DNSName: "macbook-pro.tail0000.ts.net", Online: true, IP: "100.64.0.1", OS: "macos"}
		if self == "mini" {
			return &tailnet.Status{Self: mini, Suffix: "tail0000.ts.net", Peers: []tailnet.Peer{ft, mbp}}, nil
		}
		return &tailnet.Status{Self: mbp, Suffix: "tail0000.ts.net", Peers: []tailnet.Peer{ft, mini}}, nil
	}
}

func (l *lab) setFT(up bool) { l.mu.Lock(); l.ftUp = up; l.mu.Unlock() }

// TestEndToEndHub: a real hub (hub.Serve) on loopback, and main's real App wiring (newApp) as the MacBook client,
// with only the dialer, the local tailscale status, the output buffers and the file paths swapped.
func TestEndToEndHub(t *testing.T) {
	dir := t.TempDir()
	l := &lab{}

	// the hub, on the mini
	hubHosts := filepath.Join(dir, "mini-hosts.toml")
	os.WriteFile(hubHosts, []byte(`relay = "mini"
[hub]
allow = ["owner@example.com"]
[[host]]
name = "mini"
[[host]]
name = "fabric-twin"
user = "krish"
mac = "aa:bb:cc:dd:ee:01"
tmux = "lab"
`), 0o600)
	var hubAddr string
	ready := make(chan struct{})
	hubCtx, stopHub := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- hub.Serve(hubCtx, hub.Options{
			HostsPath: hubHosts,
			StateDir:  filepath.Join(dir, "hubstate"),
			Stderr:    io.Discard,
			Status:    l.status("mini"),
			Whois: func(_ context.Context, a netip.Addr) (hub.Caller, error) {
				if a.String() == "100.64.0.1" {
					return hub.Caller{Login: "owner@example.com", Device: "macbook-pro"}, nil
				}
				return hub.Caller{}, errors.New("unknown")
			},
			IPs:  func(context.Context) ([]string, error) { return []string{"100.64.0.10"}, nil },
			Dial: func(context.Context, string) error { return errors.New("no ssh probe in this test") },
			SendWOL: func(mac net.HardwareAddr, _ string) error {
				l.mu.Lock()
				l.sent = append(l.sent, mac.String())
				l.mu.Unlock()
				return nil
			},
			Now: time.Now,
			Listen: func(_, _ string) (net.Listener, error) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				hubAddr = ln.Addr().String()
				return asOwner{ln}, nil
			},
			PollEvery: 20 * time.Millisecond,
			LongPoll:  2 * time.Second,
			Ready:     func([]string) { close(ready) },
		})
	}()
	select {
	case <-ready:
	case err := <-served:
		t.Fatalf("hub: %v", err)
	}

	// the MacBook: a hosts file with only hub_host, and main's wiring
	clientHosts := filepath.Join(dir, "hosts.toml")
	os.WriteFile(clientHosts, []byte("hub_host = \"mini\"\n"), 0o600)
	var dialed []string
	app := newApp(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return (&net.Dialer{}).DialContext(ctx, network, hubAddr)
	})
	out, errOut := &syncBuffer{}, &syncBuffer{}
	app.Stdout, app.Stderr = out, errOut
	app.HostsPath = clientHosts
	app.Status = l.status("macbook-pro")
	app.ControlDir = filepath.Join(dir, "cm")
	app.CachePath = filepath.Join(app.ControlDir, "hosts.json")
	app.Exec = func(context.Context, []string) (int, error) { return 0, errors.New("this test runs no ssh") }
	run := func(args ...string) int { return app.Run(context.Background(), args) }

	// ls: the hub's view (it sees mini as up: it runs there)
	waitFor(t, func() bool { out.Reset(); run("ls"); return strings.Contains(out.String(), "fabric-twin") })
	if !fieldsLine(out.String(), "mini up macos 100.64.0.10") || !fieldsLine(out.String(), "fabric-twin asleep windows 100.64.0.3") ||
		!strings.Contains(out.String(), "SINCE") {
		t.Fatalf("ls:\n%s%s", out, errOut)
	}
	if len(dialed) == 0 || dialed[0] != "mini:7300" {
		t.Errorf("client dialed %v, want the hub's MagicDNS name", dialed)
	}

	// wake goes through the hub, which sends the MAC it holds
	if code := run("wake", "fabric-twin", "--no-wait"); code != 0 {
		t.Fatalf("wake: %d %s", code, errOut)
	}
	l.mu.Lock()
	sent := append([]string(nil), l.sent...)
	l.mu.Unlock()
	if len(sent) != 1 || sent[0] != "aa:bb:cc:dd:ee:01" || !strings.Contains(errOut.String(), "via the hub") {
		t.Errorf("hub sent %v; stderr %q", sent, errOut)
	}

	// watch: history first, then a live change
	out.Reset()
	wctx, stopWatch := context.WithCancel(context.Background())
	watched := make(chan int, 1)
	go func() { watched <- app.Run(wctx, []string{"watch"}) }()
	waitFor(t, func() bool { return strings.Contains(out.String(), "(start) -> asleep") })
	l.setFT(true) // the wake worked: back on the tailnet (the test's port-22 probe never answers: unreachable)
	waitFor(t, func() bool { return strings.Contains(out.String(), "asleep -> unreachable") })
	stopWatch()
	if code := <-watched; code != 0 {
		t.Errorf("watch exit %d: %s", code, errOut)
	}

	// the hub stops: one notice, then direct mode from the cached list
	stopHub()
	if err := <-served; err != nil {
		t.Fatalf("hub stop: %v", err)
	}
	out.Reset()
	errOut.Reset()
	if code := run("ls"); code != 0 {
		t.Fatalf("fallback ls: %d %s", code, errOut)
	}
	if !strings.Contains(errOut.String(), "hub mini unreachable") || !strings.Contains(errOut.String(), "hosts cached") ||
		!fieldsLine(out.String(), "fabric-twin up windows") || !strings.Contains(out.String(), "LAST SEEN") {
		t.Errorf("fallback\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out")
}

func fieldsLine(out, prefix string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.Join(strings.Fields(line), " "), prefix) {
			return true
		}
	}
	return false
}
