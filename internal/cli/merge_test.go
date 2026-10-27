package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/hubclient"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

// every way a hub or cached host can collide with a local one: it is dropped, and the local host is untouched
func TestMergeCollisions(t *testing.T) {
	local := []inventory.Host{{Name: "nas", Tailnet: "nas-box", User: "krish", MAC: "aa:bb:cc:dd:ee:07"}}
	for _, o := range []inventory.Host{
		{Name: "nas", Tailnet: "evil", User: "root", HubWakeable: true}, // same name
		{Name: "x", Tailnet: "nas-box", User: "root"},                   // same tailnet
		{Name: "nas-box", Tailnet: "evil", User: "root"},                // name = local tailnet
		{Name: "y", Tailnet: "nas", User: "root"},                       // tailnet = local name
	} {
		got := merge(local, []inventory.Host{o})
		if len(got) != 1 || got[0].Tailnet != "nas-box" || got[0].User != "krish" || got[0].MAC == "" {
			t.Errorf("%+v: merged %+v", o, got)
		}
	}
	if got := merge(local, []inventory.Host{{Name: "nas", Tailnet: "x", HubWakeable: true}}); !got[0].HubWakeable {
		t.Error("a local host takes HubWakeable from the hub's entry of the same name")
	}
	if got := merge(local, []inventory.Host{{Name: "korg", Tailnet: "korg"}}); len(got) != 2 {
		t.Errorf("no collision: %+v", got)
	}
}

// review R1/R4: a failed hub answer never replaces the cache; a bad cache is said, not silently ignored
func TestCacheSurvivesBadAnswer(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, _ := withHub(t, h)
	h.run("ls")
	f.err = errors.New("hub: the answer has no host list")
	h.run("ls")
	if c, _, err := hubclient.LoadCache(h.app.CachePath); err != nil || len(c.Hosts) != 2 {
		t.Errorf("cache after a bad answer: %v %v", c, err)
	}
	os.WriteFile(h.app.CachePath, []byte(`{"hosts": [{"name": "-oProxyCommand=x", "tailnet": "a"}]}`), 0o600)
	h.errOut.Reset()
	h.run("ls")
	if !strings.Contains(h.errOut.String(), "ignoring the cached host list") {
		t.Errorf("a refused cache was not reported: %q", h.errOut)
	}
}

// review R3: the cached relay is used when the local file names none; a cached HubWakeable never means the hub
// when the hub is down
func TestFallbackCachedRelay(t *testing.T) {
	h := newHarness(t, clientHosts+"[[host]]\nname = \"fabric-twin\"\nmac = \"aa:bb:cc:dd:ee:01\"\n")
	f, ssh := withHub(t, h)
	h.run("ls") // caches relay = mini and the hub's mini
	f.err = errors.New("hub down")
	h.app.Exec = func(ctx context.Context, argv []string) (int, error) {
		if strings.Contains(strings.Join(argv, " "), "labctl wol") {
			h.tn.set("fabric-twin", true)
		}
		return ssh.exec(ctx, argv)
	}
	if code := h.run("wake", "fabric-twin"); code != 0 || !strings.Contains(ssh.last(), "-- mini ") {
		t.Errorf("relay from the cache: exit %d, %s\n%s", code, ssh.last(), h.errOut)
	}

	// korg is wakeable through the hub only: with the hub down, a clear error, no crash
	h2 := newHarness(t, clientHosts)
	f2, _ := withHub(t, h2)
	f2.hosts.Hosts = append(f2.hosts.Hosts, hub.HostInfo{Name: "phone", Tailnet: "phone", Tmux: "main", Wakeable: true})
	h2.run("ls")
	f2.err = errors.New("hub down")
	if code := h2.run("wake", "phone"); code == 0 || !strings.Contains(h2.errOut.String(), "no mac") {
		t.Errorf("hub-only host with the hub down: exit %d, %q", code, h2.errOut)
	}
}

// review R6/R7: a wake the hub already sent is waited for, not an error; the no-mac message names the hub
func TestHubWakeMessages(t *testing.T) {
	h := newHarness(t, clientHosts)
	f, ssh := withHub(t, h)
	f.wakeErr = hubclient.ErrRecentlyWoken
	calls := 0
	inner := h.app.Status
	h.app.Status = func(ctx context.Context) (*tailnet.Status, error) {
		if calls++; calls > 2 {
			h.tn.set("fabric-twin", true)
		}
		return inner(ctx)
	}
	if code := h.run("fabric-twin", "uptime"); code != 0 || !strings.HasSuffix(ssh.last(), "-T -- krish@fabric-twin uptime") {
		t.Errorf("auto-wake after a recent wake: exit %d, %s\n%s", code, ssh.last(), h.errOut)
	}
	h.tn.set("mini", false)
	h.errOut.Reset()
	if code := h.run("wake", "mini"); code == 0 || !strings.Contains(h.errOut.String(), "the hub has no mac for mini") {
		t.Errorf("exit %d, %q", code, h.errOut)
	}
}
