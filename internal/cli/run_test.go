package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH records every argv labctl would exec and answers with a chosen exit code.
type fakeSSH struct {
	calls [][]string
	code  int
}

func (f *fakeSSH) exec(_ context.Context, argv []string) (int, error) {
	f.calls = append(f.calls, argv)
	return f.code, nil
}

func (f *fakeSSH) last() string {
	if len(f.calls) == 0 {
		return ""
	}
	return strings.Join(f.calls[len(f.calls)-1], " ")
}

func withSSH(t *testing.T, h *harness) *fakeSSH {
	f := &fakeSSH{}
	h.app.Exec = f.exec
	h.app.ControlDir = filepath.Join(t.TempDir(), "cm")
	return f
}

func TestRun(t *testing.T) {
	h := newHarness(t, hostsFile)
	ssh := withSSH(t, h)
	if code := h.run("mini", "git", "commit", "-m", "fix bgp"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	got := ssh.last()
	for _, want := range []string{"ControlMaster=auto", "ControlPersist=10m", "ServerAliveInterval=5", "-T mini 'git' 'commit' '-m' 'fix bgp'"} {
		if !strings.Contains(got, want) {
			t.Errorf("argv lacks %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "ControlPath="+h.app.ControlDir+"/cm-%C") {
		t.Errorf("argv does not use the control dir:\n%s", got)
	}
	h.run("mini", "make a && make b")
	if !strings.HasSuffix(ssh.last(), "-T mini make a && make b") {
		t.Errorf("one argument must pass as a shell string:\n%s", ssh.last())
	}
}

func TestShell(t *testing.T) {
	h := newHarness(t, hostsFile)
	ssh := withSSH(t, h)
	h.tn.set("fabric-twin", true)
	if code := h.run("fabric-twin"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if !strings.Contains(ssh.last(), "-t fabric-twin tmux attach -t 'lab'") {
		t.Errorf("shell argv:\n%s", ssh.last())
	}
	if code := h.run("MINI"); code != 0 || !strings.Contains(ssh.last(), "-t mini tmux attach -t 'main'") {
		t.Errorf("host names are case-insensitive and tmux defaults to main: exit %d\n%s", code, ssh.last())
	}
}

func TestExitCode(t *testing.T) {
	h := newHarness(t, hostsFile)
	ssh := withSSH(t, h)
	ssh.code = 3
	if code := h.run("mini", "false"); code != 3 {
		t.Errorf("exit %d, want the remote's 3", code)
	}
	if h.errOut.Len() != 0 {
		t.Errorf("a passed-through exit code must print nothing, got %q", h.errOut)
	}
	if code := h.run("ghost", "ls"); code != 1 || !strings.Contains(h.errOut.String(), `"ghost"`) {
		t.Errorf("unknown host: exit %d, %q", code, h.errOut)
	}
	if len(ssh.calls) != 1 {
		t.Errorf("unknown host must not run ssh, calls: %v", ssh.calls)
	}
}

func TestOff(t *testing.T) {
	h := newHarness(t, hostsFile)
	ssh := withSSH(t, h)
	ssh.code = 255 // no master running for some hosts: not an error
	if code := h.run("off"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errOut)
	}
	if len(ssh.calls) != 3 {
		t.Fatalf("off must close every host, calls: %v", ssh.calls)
	}
	for _, c := range ssh.calls {
		if !strings.Contains(strings.Join(c, " "), "-O exit") {
			t.Errorf("not an exit: %v", c)
		}
	}
	ssh.calls = nil
	h.run("off", "fabric-twin")
	if len(ssh.calls) != 1 || !strings.HasSuffix(ssh.last(), "-O exit fabric-twin") {
		t.Errorf("off <host>: %v", ssh.calls)
	}
}
