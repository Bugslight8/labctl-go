package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEndToEnd builds the real binary and runs it with fake `tailscale` and `ssh` programs first on PATH (T5:
// nothing reaches a real host or the real tailnet). The fake tailscale reports fabric-twin asleep until the fake
// ssh has carried a `labctl wol` to the relay, then online.
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "labctl")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	fake := filepath.Join(dir, "fakebin")
	state := filepath.Join(dir, "state")
	for _, d := range []string{fake, state} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	status := func(online bool) string {
		on := "false"
		if online {
			on = "true"
		}
		return `{"BackendState": "Running",
 "Self": {"DNSName": "macbook-pro.tail0000.ts.net.", "OS": "macOS", "Online": true},
 "Peer": {
  "a": {"DNSName": "mini.tail0000.ts.net.", "HostName": "Mac-mini", "OS": "macOS", "Online": true, "TailscaleIPs": ["100.64.0.2"]},
  "b": {"DNSName": "fabric-twin.tail0000.ts.net.", "HostName": "DESKTOP-7", "OS": "windows", "Online": ` + on + `,
        "LastSeen": "2026-10-26T09:00:00Z", "TailscaleIPs": ["100.64.0.3"]}}}`
	}
	write := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(state, "asleep.json"), status(false), 0o600)
	write(filepath.Join(state, "up.json"), status(true), 0o600)
	write(filepath.Join(fake, "tailscale"), `#!/bin/sh
[ "$1 $2" = "status --json" ] || exit 2
if [ -f "$FAKE_STATE/woke" ]; then cat "$FAKE_STATE/up.json"; else cat "$FAKE_STATE/asleep.json"; fi
`, 0o700)
	write(filepath.Join(fake, "ssh"), `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_STATE/ssh.log"
case "$*" in *"labctl wol "*) : > "$FAKE_STATE/woke" ;; esac
echo "fake-ssh"
exit "${FAKE_SSH_EXIT:-0}"
`, 0o700)

	home := filepath.Join(dir, "home")
	hosts := filepath.Join(home, ".config", "labctl", "hosts.toml")
	env := append(os.Environ(), "PATH="+fake+":/usr/bin:/bin", "HOME="+home, "FAKE_STATE="+state, "LABCTL_HOSTS=")
	run := func(extraEnv []string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(append([]string(nil), env...), extraEnv...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), code
	}
	sshLog := func() string { b, _ := os.ReadFile(filepath.Join(state, "ssh.log")); return string(b) }

	// hosts init writes the default hosts file from the tailnet
	if out, code := run(nil, "hosts", "init"); code != 0 || !strings.Contains(out, "wrote 2 hosts to "+hosts) {
		t.Fatalf("hosts init: exit %d\n%s", code, out)
	}
	data, _ := os.ReadFile(hosts)
	edited := strings.Replace(string(data), `# relay = "mini"`, `relay = "mini"`, 1)
	edited = strings.Replace(edited, "name = \"fabric-twin\"\n", "name = \"fabric-twin\"\nmac = \"aa:bb:cc:dd:ee:01\"\n", 1)
	write(hosts, edited, 0o600)

	// ls: no ssh at all
	out, code := run(nil, "ls")
	if code != 0 || !hasFields(out, "fabric-twin asleep windows 100.64.0.3") || !strings.Contains(out, "wakeable") {
		t.Fatalf("ls: exit %d\n%s", code, out)
	}
	if sshLog() != "" {
		t.Fatalf("ls ran ssh:\n%s", sshLog())
	}

	// wake: the relay sends the packet, then the host shows up on the tailnet
	out, code = run(nil, "wake", "fabric-twin")
	if code != 0 || !strings.Contains(out, "fabric-twin is up") {
		t.Fatalf("wake: exit %d\n%s", code, out)
	}
	if !strings.Contains(sshLog(), "-T mini PATH=") || !strings.Contains(sshLog(), "labctl wol 'aa:bb:cc:dd:ee:01'") {
		t.Fatalf("relay call:\n%s", sshLog())
	}
	if fi, err := os.Stat(filepath.Join(home, ".cache", "labctl")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("control dir: %v %v", fi, err)
	}

	// auto-wake: a command for an asleep host wakes it first, then runs
	os.Remove(filepath.Join(state, "woke"))
	os.Remove(filepath.Join(state, "ssh.log"))
	out, code = run(nil, "fabric-twin", "uptime")
	lines := strings.Split(strings.TrimSpace(sshLog()), "\n")
	if code != 0 || len(lines) != 2 || !strings.Contains(lines[0], "labctl wol") || !strings.HasSuffix(lines[1], "-T fabric-twin uptime") {
		t.Fatalf("auto-wake: exit %d\n%s\nssh log:\n%s", code, out, sshLog())
	}

	// the remote exit code passes through
	if _, code = run([]string{"FAKE_SSH_EXIT=7"}, "mini", "false"); code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}

	// wol sends a real magic packet (to a local listener, not the LAN)
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if out, code = run(nil, "wol", "aa:bb:cc:dd:ee:01", "--to", l.LocalAddr().String()); code != 0 {
		t.Fatalf("wol: exit %d\n%s", code, out)
	}
	buf := make([]byte, 200)
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := l.ReadFromUDP(buf); err != nil || n != 102 {
		t.Fatalf("magic packet: %d bytes, %v", n, err)
	}
}

// hasFields reports whether some line of out has exactly these whitespace-separated leading fields.
func hasFields(out, fields string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.Join(strings.Fields(line), " "), fields) {
			return true
		}
	}
	return false
}
