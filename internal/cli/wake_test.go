package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/tailnet"
)

// wakeHarness: a fake clock, and a fake relay. When the relay runs `labctl wol <mac>`, the woken host comes online
// after upAfter more tailnet polls (upAfter < 0: never).
type wakeHarness struct {
	*harness
	ssh     *fakeSSH
	clock   time.Time
	upAfter int
	woke    string // host to bring up
}

func newWakeHarness(t *testing.T, upAfter int) *wakeHarness {
	w := &wakeHarness{harness: newHarness(t, hostsFile), clock: now, upAfter: upAfter, woke: "fabric-twin"}
	w.ssh = withSSH(t, w.harness)
	w.app.Now = func() time.Time { return w.clock }
	w.app.Sleep = func(d time.Duration) { w.clock = w.clock.Add(d) }
	polls, sent := 0, false
	inner := w.tn.status
	w.app.Status = func(ctx context.Context) (*tailnet.Status, error) {
		if sent && w.upAfter >= 0 {
			if polls >= w.upAfter {
				w.tn.set(w.woke, true)
			}
			polls++
		}
		return inner(ctx)
	}
	w.app.Exec = func(ctx context.Context, argv []string) (int, error) {
		if strings.Contains(strings.Join(argv, " "), "labctl wol ") {
			sent = true
		}
		return w.ssh.exec(ctx, argv)
	}
	return w
}

func TestWake(t *testing.T) {
	w := newWakeHarness(t, 3)
	if code := w.run("wake", "fabric-twin"); code != 0 {
		t.Fatalf("exit %d: %s", code, w.errOut)
	}
	relay := w.ssh.calls[0]
	got := strings.Join(relay, " ")
	if !strings.Contains(got, "ssh -n ") || !strings.Contains(got, "-T -- mini ") || !strings.HasSuffix(got, "labctl wol 'aa:bb:cc:dd:ee:01' >&2") {
		t.Errorf("relay argv:\n%s", got)
	}
	if !strings.Contains(w.errOut.String(), "fabric-twin is up") || w.out.Len() != 0 {
		t.Errorf("progress must go to stderr only; stdout %q, stderr %q", w.out, w.errOut)
	}
	// upAfter 3: polls 1-3 still asleep, poll 4 sees it up, each poll after a 2 s sleep
	if waited := w.clock.Sub(now); waited != 8*time.Second {
		t.Errorf("waited %v on the fake clock, want 4 polls of 2 s", waited)
	}
}

func TestWakeNoWait(t *testing.T) {
	w := newWakeHarness(t, -1)
	if code := w.run("wake", "fabric-twin", "--no-wait"); code != 0 {
		t.Fatalf("exit %d: %s", code, w.errOut)
	}
	if w.clock != now {
		t.Errorf("--no-wait waited %v", w.clock.Sub(now))
	}
}

func TestWakeTimeout(t *testing.T) {
	w := newWakeHarness(t, -1)
	if code := w.run("wake", "fabric-twin"); code == 0 {
		t.Fatal("wake of a host that never comes up succeeded")
	}
	if w.clock.Sub(now) < 120*time.Second {
		t.Errorf("gave up after %v, want 120 s", w.clock.Sub(now))
	}
	if !strings.Contains(w.errOut.String(), "Wake-on-LAN") {
		t.Errorf("timeout message does not explain the WoL settings: %s", w.errOut)
	}
}

func TestWakeRefusals(t *testing.T) {
	cases := map[string][]string{
		"no mac":       {"wake", "mini"},
		"unknown host": {"wake", "ghost"},
		"no host":      {"wake"},
	}
	for what, args := range cases {
		w := newWakeHarness(t, 0)
		w.tn.set("mini", false) // even when asleep, mini has no mac
		if code := w.run(args...); code == 0 {
			t.Errorf("%s: succeeded", what)
		}
		if len(w.ssh.calls) != 0 {
			t.Errorf("%s: ran ssh %v", what, w.ssh.calls)
		}
	}
	w := newWakeHarness(t, 0)
	w.tn.set("fabric-twin", true)
	if code := w.run("wake", "fabric-twin"); code != 0 || len(w.ssh.calls) != 0 || !strings.Contains(w.out.String(), "already up") {
		t.Errorf("waking an up host: exit %d, calls %v, out %q", code, w.ssh.calls, w.out)
	}
	w = newWakeHarness(t, 0)
	w.tn.set("mini", false)
	if code := w.run("wake", "fabric-twin"); code == 0 || !strings.Contains(w.errOut.String(), "relay") {
		t.Errorf("relay offline: exit %d, %q", code, w.errOut)
	}
}

func TestAutoWake(t *testing.T) {
	w := newWakeHarness(t, 1)
	if code := w.run("fabric-twin", "uptime"); code != 0 {
		t.Fatalf("exit %d: %s", code, w.errOut)
	}
	if len(w.ssh.calls) != 2 {
		t.Fatalf("want the relay wake then the command, got %v", w.ssh.calls)
	}
	if !strings.HasSuffix(strings.Join(w.ssh.calls[1], " "), "-T -- fabric-twin uptime") {
		t.Errorf("second call: %v", w.ssh.calls[1])
	}
	if w.out.Len() != 0 {
		t.Errorf("auto-wake wrote to stdout, which belongs to the command: %q", w.out)
	}

	// an up host runs at once, with a single status query
	w = newWakeHarness(t, 0)
	w.tn.set("fabric-twin", true)
	w.run("fabric-twin", "uptime")
	if len(w.ssh.calls) != 1 || w.tn.queries != 1 {
		t.Errorf("up host: calls %v, status queries %d", w.ssh.calls, w.tn.queries)
	}

	// a host that cannot be woken is tried anyway, with a warning
	w = newWakeHarness(t, 0)
	w.tn.set("mini", false)
	w.run("mini", "uptime")
	if len(w.ssh.calls) != 1 || !strings.Contains(w.errOut.String(), "asleep") {
		t.Errorf("unwakeable host: calls %v, stderr %q", w.ssh.calls, w.errOut)
	}

	// tailscale unavailable: still try ssh
	w = newWakeHarness(t, 0)
	w.app.Status = func(context.Context) (*tailnet.Status, error) { return nil, errors.New("no tailscale") }
	if code := w.run("mini", "uptime"); code != 0 || len(w.ssh.calls) != 1 {
		t.Errorf("no tailscale: exit %d, calls %v", code, w.ssh.calls)
	}
}

func TestWol(t *testing.T) {
	h := newHarness(t, "")
	var sent []string
	h.app.SendWOL = func(mac net.HardwareAddr, addr string) error {
		sent = append(sent, mac.String()+" "+addr)
		return nil
	}
	if code := h.run("wol", "AA-BB-CC-DD-EE-01"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if len(sent) != 1 || sent[0] != "aa:bb:cc:dd:ee:01 255.255.255.255:9" {
		t.Errorf("sent %v", sent)
	}
	for _, bad := range [][]string{{"wol"}, {"wol", "nope"}, {"wol", "00:00:5e:10:00:00:00:01"}} {
		if code := h.run(bad...); code == 0 {
			t.Errorf("%v succeeded", bad)
		}
	}
	if len(sent) != 1 {
		t.Errorf("bad input sent packets: %v", sent)
	}
}

// a tailscale that keeps failing while a host wakes must surface its error, not the Wake-on-LAN checklist
func TestWakePollError(t *testing.T) {
	w := newWakeHarness(t, -1)
	inner := w.app.Status
	w.app.Status = func(ctx context.Context) (*tailnet.Status, error) {
		if len(w.ssh.calls) > 0 {
			return nil, errors.New("failed to connect to local tailscaled")
		}
		return inner(ctx)
	}
	if code := w.run("wake", "fabric-twin"); code == 0 {
		t.Fatal("succeeded")
	}
	if !strings.Contains(w.errOut.String(), "tailscaled") || strings.Contains(w.errOut.String(), "Wake-on-LAN") {
		t.Errorf("stderr %q", w.errOut)
	}
	if w.clock.Sub(now) >= wakeTimeout {
		t.Errorf("waited the full timeout (%v) despite tailscale failing", w.clock.Sub(now))
	}
}

// a host that is not on the tailnet can be woken, but labctl cannot see it come up: send and return
func TestWakeNotOnTailnet(t *testing.T) {
	w := newWakeHarness(t, -1)
	hosts := strings.Replace(hostsFile, "name = \"nas\"\n", "name = \"nas\"\nmac = \"aa:bb:cc:dd:ee:02\"\n", 1)
	if err := os.WriteFile(w.hosts, []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.run("wake", "nas"); code != 0 {
		t.Fatalf("exit %d: %s", code, w.errOut)
	}
	if len(w.ssh.calls) != 1 || w.clock != now || !strings.Contains(w.errOut.String(), "not on the tailnet") {
		t.Errorf("calls %v, waited %v, stderr %q", w.ssh.calls, w.clock.Sub(now), w.errOut)
	}
}

// the "cannot be woken" warning must name the real reason, not a generic one
func TestAutoWakeReason(t *testing.T) {
	cases := []struct{ hosts, host, want string }{
		{"relay = \"mini\"\n[[host]]\nname = \"mini\"\nmac = \"aa:bb:cc:dd:ee:09\"\n", "mini", "is the relay"},
		{"relay = \"mini\"\n[[host]]\nname = \"mini\"\n[[host]]\nname = \"fabric-twin\"\n", "fabric-twin", "no mac"},
		{"[[host]]\nname = \"fabric-twin\"\nmac = \"aa:bb:cc:dd:ee:01\"\n", "fabric-twin", "no relay"},
	}
	for _, c := range cases {
		w := newWakeHarness(t, 0)
		if err := os.WriteFile(w.hosts, []byte(c.hosts), 0o600); err != nil {
			t.Fatal(err)
		}
		w.tn.set("mini", false)
		w.run(c.host, "uptime")
		if got := w.errOut.String(); !strings.Contains(got, c.want) || strings.Contains(got, "needs mac and relay") {
			t.Errorf("%s: stderr %q, want the reason %q", c.host, got, c.want)
		}
	}
}
