package sshx

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Bugslight8/labctl/internal/inventory"
)

// T2: what Quote produces, run through a real POSIX shell, must give back exactly the original arguments.
func TestQuoteRoundTrip(t *testing.T) {
	cases := [][]string{
		{"git", "commit", "-m", "fix bgp"},
		{"echo", "a;b", "$HOME", "`id`", "$(reboot)", "x && y", "|", ">out"},
		{"it's", `"double"`, `back\slash`, "", "  spaced  "},
		{"new\nline", "tab\there", "ünïcödé", "*", "~", "#notacomment"},
	}
	for _, args := range cases {
		out, err := exec.Command("/bin/sh", "-c", `printf '%s\0' `+Quote(args)).Output()
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		if !reflect.DeepEqual(got, args) {
			t.Errorf("round trip\n got %q\nwant %q", got, args)
		}
	}
}

func TestRemoteCommand(t *testing.T) {
	if got := RemoteCommand([]string{"make a && make b"}); got != "make a && make b" {
		t.Errorf("one argument must pass as a shell string, got %q", got)
	}
	if got := RemoteCommand([]string{"echo", "a b"}); got != `'echo' 'a b'` {
		t.Errorf("several arguments must be quoted one by one, got %q", got)
	}
}

// T4: the ControlMaster socket directory must be private to this user.
func TestControlDirPerms(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "labctl")
	if err := EnsureControlDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created with %v (%v), want 0700", fi.Mode().Perm(), err)
	}
	for _, mode := range []os.FileMode{0o770, 0o707, 0o755} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := EnsureControlDir(dir); err == nil {
			t.Errorf("accepted a directory with mode %v", mode)
		}
	}
	file := filepath.Join(base, "notadir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureControlDir(file); err == nil {
		t.Error("accepted a file")
	}
}

func TestArgv(t *testing.T) {
	h := inventory.Host{Name: "fabric-twin", Tailnet: "korg", User: "krish", Tmux: "lab"}
	got := Argv(h, "/c", "make deploy", false)
	want := []string{"ssh", "-o", "ConnectTimeout=10", "-o", "ControlMaster=auto", "-o", "ControlPath=/c/cm-%C",
		"-o", "ControlPersist=10m", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
		"-T", "--", "krish@korg", "make deploy"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Argv\n got %q\nwant %q", got, want)
	}
	h.User = ""
	tty := Argv(h, "/c", ShellCommand(h), true)
	if tty[len(tty)-4] != "-t" || tty[len(tty)-3] != "--" || tty[len(tty)-2] != "korg" {
		t.Errorf("interactive argv %q", tty)
	}
	if exit := OffArgv(h, "/c"); strings.Join(exit[len(exit)-4:], " ") != "-O exit -- korg" {
		t.Errorf("OffArgv %q", exit)
	}
}

func TestShellCommand(t *testing.T) {
	got := ShellCommand(inventory.Host{Tmux: "lab"})
	if !strings.HasPrefix(got, "tmux attach -t 'lab' 2>/dev/null || tmux new -s 'lab'") {
		t.Errorf("tmux shell command %q", got)
	}
	if got := ShellCommand(inventory.Host{Tmux: ""}); got != "" {
		t.Errorf("no tmux must mean a plain login shell (empty remote command), got %q", got)
	}
}

// Security M1: a one-argument command is passed unquoted, so it must never be read as an ssh option.
func TestOptionInjection(t *testing.T) {
	h := inventory.Host{Name: "a", Tailnet: "a"}
	for _, argv := range [][]string{
		Argv(h, "/c", RemoteCommand([]string{"-oProxyCommand=touch /tmp/pwned"}), false),
		Argv(h, "/c", "-oProxyCommand=x", true),
		OffArgv(h, "/c"),
	} {
		end := -1
		for i, a := range argv {
			if a == "--" {
				end = i
				break
			}
		}
		if end < 0 || argv[end+1] != "a" {
			t.Errorf("no -- right before the target: %q", argv)
		}
	}
}
