package hub

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchdPlist(t *testing.T) {
	p := Plist("/Users/me/.local/bin/labctl", "/Users/me/.config/labctl/hosts & more.toml", "/Users/me/.local/state/labctl")
	for _, want := range []string{
		"<string>com.labctl.hub</string>",
		"<string>/Users/me/.local/bin/labctl</string>\n\t\t<string>hub</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>LABCTL_HOSTS</key>\n\t\t<string>/Users/me/.config/labctl/hosts &amp; more.toml</string>",
		"/usr/local/bin:/opt/homebrew/bin", // launchd's PATH lacks the tailscale CLI otherwise
		"<string>/Users/me/.local/state/labctl/hub.log</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, " & ") {
		t.Error("an unescaped & would make the plist invalid XML")
	}
}

func TestLaunchd(t *testing.T) {
	home := t.TempDir()
	var calls []string
	failBootstrap := false
	l := &Launchd{
		Dir: filepath.Join(home, "Library", "LaunchAgents"),
		UID: 501,
		Run: func(args ...string) error {
			calls = append(calls, strings.Join(args, " "))
			if failBootstrap && args[0] == "bootstrap" {
				return errors.New("Bootstrap failed: 125: Domain does not support specified action")
			}
			return nil
		},
	}
	plist := filepath.Join(l.Dir, "com.labctl.hub.plist")
	state := filepath.Join(home, ".local", "state", "labctl")
	msg, err := l.Install("/x/labctl", "/x/hosts.toml", state)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bootout gui/501/com.labctl.hub|bootstrap gui/501 " + plist; strings.Join(calls, "|") != want {
		t.Errorf("calls %q, want %q", calls, want)
	}
	if fi, err := os.Stat(plist); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("plist: %v %v", fi, err)
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir: %v %v", fi, err)
	}
	if !strings.Contains(msg, "installed") {
		t.Errorf("message %q", msg)
	}

	// bootstrap refused (e.g. over ssh with no GUI session): the plist stays, and the message gives the fallback
	calls, failBootstrap = nil, true
	msg, err = l.Install("/x/labctl", "/x/hosts.toml", state)
	if err != nil || !strings.Contains(msg, "launchctl load -w "+plist) {
		t.Errorf("fallback: %q %v", msg, err)
	}

	calls = nil
	if err := l.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, "|") != "bootout gui/501/com.labctl.hub" {
		t.Errorf("uninstall calls %q", calls)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Errorf("plist still there: %v", err)
	}
	// not loaded is fine; any other launchctl failure must be reported, not printed as success
	l.Run = func(...string) error { return errors.New("Boot-out failed: 3: No such process") }
	if err := l.Uninstall(); err != nil {
		t.Errorf("uninstall when not loaded: %v", err)
	}
	l.Run = func(...string) error { return errors.New("Boot-out failed: 5: Input/output error") }
	if err := l.Uninstall(); err == nil {
		t.Error("a real bootout failure was swallowed")
	}
}
