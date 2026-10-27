package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// fakeTailnet is a tailnet whose state the test controls.
type fakeTailnet struct {
	peers   []tailnet.Peer
	queries int
}

func (f *fakeTailnet) status(context.Context) (*tailnet.Status, error) {
	f.queries++
	return &tailnet.Status{Self: tailnet.Peer{Name: "macbook-pro"}, Peers: append([]tailnet.Peer(nil), f.peers...)}, nil
}

func (f *fakeTailnet) set(name string, online bool) {
	for i := range f.peers {
		if f.peers[i].Name == name {
			f.peers[i].Online = online
		}
	}
}

func newFakeTailnet() *fakeTailnet {
	return &fakeTailnet{peers: []tailnet.Peer{
		{Name: "fabric-twin", HostName: "DESKTOP-7", OS: "windows", IP: "100.64.0.3", LastSeen: now.Add(-3 * time.Hour)},
		{Name: "mini", HostName: "Mac-mini", OS: "macos", Online: true, IP: "100.64.0.2"},
		{Name: "phone", HostName: "iPhone", OS: "ios", Online: true, IP: "100.64.0.9"},
		{Name: "pi", HostName: "localhost", OS: "linux", Online: true, IP: "100.64.0.4"},
	}}
}

const hostsFile = `
relay = "mini"

[[host]]
name = "mini"

[[host]]
name = "fabric-twin"
mac = "aa:bb:cc:dd:ee:01"
tmux = "lab"

[[host]]
name = "nas"
`

// harness builds an App with fakes and a hosts file; out and errOut collect what the user sees.
type harness struct {
	app         *App
	tn          *fakeTailnet
	out, errOut *bytes.Buffer
	hosts       string
}

func newHarness(t *testing.T, hosts string) *harness {
	t.Helper()
	h := &harness{tn: newFakeTailnet(), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	h.hosts = filepath.Join(t.TempDir(), "labctl", "hosts.toml")
	if hosts != "" {
		if err := os.MkdirAll(filepath.Dir(h.hosts), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.hosts, []byte(hosts), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.app = &App{
		Stdout: h.out, Stderr: h.errOut,
		HostsPath: h.hosts,
		Status:    h.tn.status,
		Now:       func() time.Time { return now },
	}
	return h
}

func (h *harness) run(args ...string) int { return h.app.Run(context.Background(), args) }

func TestLs(t *testing.T) {
	h := newHarness(t, hostsFile)
	if code := h.run("ls"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	want := [][]string{
		{"NAME", "STATE", "OS", "ADDRESS", "LAST", "SEEN"},
		{"mini", "up", "macos", "100.64.0.2", "now", "relay"},
		{"fabric-twin", "asleep", "windows", "100.64.0.3", "3h", "ago", "wakeable"},
		{"nas", "not-on-tailnet", "-", "-", "-"},
	}
	for i, w := range want {
		if i >= len(lines) || strings.Join(strings.Fields(lines[i]), " ") != strings.Join(w, " ") {
			t.Errorf("line %d = %q, want fields %v\n%s", i, lineAt(lines, i), w, h.out)
		}
	}
	if !strings.Contains(h.out.String(), "not in the hosts file: phone, pi") {
		t.Errorf("missing the not-in-hosts-file hint:\n%s", h.out)
	}
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}

func TestLsWithoutHostsFile(t *testing.T) {
	h := newHarness(t, "")
	if code := h.run("ls"); code == 0 {
		t.Fatal("ls without a hosts file succeeded")
	}
	if !strings.Contains(h.errOut.String(), "labctl hosts init") {
		t.Errorf("error does not point at hosts init: %s", h.errOut)
	}
}

func TestHostsInit(t *testing.T) {
	h := newHarness(t, "")
	h.tn.peers = append(h.tn.peers, tailnet.Peer{Name: "-oProxyCommand=x", OS: "linux"})
	if code := h.run("hosts", "init"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	data, err := os.ReadFile(h.hosts)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("written file does not parse: %v\n%s", err, data)
	}
	var names []string
	for _, x := range inv.Hosts {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "fabric-twin,mini,phone,pi" {
		t.Errorf("hosts = %v", names)
	}
	if !strings.Contains(h.errOut.String(), "skipped") {
		t.Errorf("unsafe peer name not reported as skipped: %s", h.errOut)
	}
	if fi, _ := os.Stat(h.hosts); fi.Mode().Perm() != 0o600 {
		t.Errorf("hosts file mode %v, want 0600", fi.Mode().Perm())
	}
	if !strings.Contains(string(data), "# relay = ") || !strings.Contains(string(data), "# mac = ") {
		t.Errorf("template lacks the relay/mac hints:\n%s", data)
	}

	// never overwrites
	if code := h.run("hosts", "init"); code == 0 {
		t.Error("second hosts init succeeded")
	}
	if again, _ := os.ReadFile(h.hosts); !bytes.Equal(again, data) {
		t.Error("hosts file changed")
	}
}

func TestUsageAndVersion(t *testing.T) {
	h := newHarness(t, hostsFile)
	if code := h.run(); code != 0 || !strings.Contains(h.out.String(), "NAME") {
		t.Errorf("bare labctl should show ls: exit %d\n%s", code, h.out)
	}
	h.out.Reset()
	if code := h.run("version"); code != 0 || !strings.HasPrefix(h.out.String(), "labctl ") {
		t.Errorf("version: exit %d %q", code, h.out)
	}
	h.out.Reset()
	if code := h.run("help"); code != 0 || !strings.Contains(h.out.String(), "labctl wake") {
		t.Errorf("help: exit %d\n%s", code, h.out)
	}
}
