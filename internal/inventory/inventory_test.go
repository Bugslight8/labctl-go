package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
relay = "mini"

[[host]]
name = "mini"
os = "macos"

[[host]]
name = "fabric-twin"
tailnet = "desktop-7"
user = "krish"
os = "windows"
mac = "AA-BB-CC-DD-EE-01"
tmux = "lab"

[[host]]
name = "pi"
tmux = ""
`

func TestParse(t *testing.T) {
	inv, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Relay != "mini" || len(inv.Hosts) != 3 {
		t.Fatalf("relay=%q hosts=%d", inv.Relay, len(inv.Hosts))
	}
	mini, ft, pi := inv.Hosts[0], inv.Hosts[1], inv.Hosts[2]
	if mini.Tailnet != "mini" || mini.Tmux != "main" {
		t.Errorf("defaults: tailnet=%q tmux=%q", mini.Tailnet, mini.Tmux)
	}
	if ft.Tailnet != "desktop-7" || ft.User != "krish" || ft.Tmux != "lab" {
		t.Errorf("fabric-twin: %+v", ft)
	}
	if ft.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("mac not canonical: %q", ft.MAC)
	}
	if pi.Tmux != "" {
		t.Errorf("tmux = \"\" must mean a plain shell, got %q", pi.Tmux)
	}
}

func TestFind(t *testing.T) {
	inv, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"fabric-twin", "desktop-7", "FABRIC-TWIN"} {
		if h, ok := inv.Find(q); !ok || h.Name != "fabric-twin" {
			t.Errorf("Find(%q) = %v, %v", q, h, ok)
		}
	}
	if _, ok := inv.Find("nope"); ok {
		t.Error("Find(nope) found something")
	}
}

// T1: a field that reaches the ssh argv must not be able to become an ssh option.
func TestRejectsUnsafeFields(t *testing.T) {
	bad := map[string]string{
		"option name":    `[[host]]` + "\n" + `name = "-oProxyCommand=touch /tmp/x"`,
		"option tailnet": `[[host]]` + "\n" + `name = "a"` + "\n" + `tailnet = "-oProxyCommand=x"`,
		"option user":    `[[host]]` + "\n" + `name = "a"` + "\n" + `user = "-oProxyCommand=x"`,
		"at in user":     `[[host]]` + "\n" + `name = "a"` + "\n" + `user = "root@evil"`,
		"space":          `[[host]]` + "\n" + `name = "a b"`,
		"semicolon tmux": `[[host]]` + "\n" + `name = "a"` + "\n" + `tmux = "x;reboot"`,
		"empty name":     `[[host]]` + "\n" + `name = ""`,
		"too long":       `[[host]]` + "\n" + `name = "` + strings.Repeat("a", 64) + `"`,
		"duplicate":      `[[host]]` + "\n" + `name = "a"` + "\n[[host]]\n" + `name = "A"`,
		"unknown relay":  `relay = "ghost"` + "\n[[host]]\n" + `name = "a"`,
		"unknown key":    `[[host]]` + "\n" + `name = "a"` + "\n" + `proxy = "x"`,
	}
	for what, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

// T3: the MAC goes into a command on the relay, so only a real 6-byte MAC may pass.
func TestRejectsBadMAC(t *testing.T) {
	for _, mac := range []string{
		"aa:bb:cc:dd:ee:ff; reboot",
		"$(reboot)",
		"aa:bb:cc:dd:ee",
		"00:00:5e:10:00:00:00:01", // 8 bytes (EUI-64)
		"not-a-mac",
	} {
		src := "[[host]]\nname = \"a\"\nmac = \"" + mac + "\"\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("mac %q accepted", mac)
		}
	}
}

func TestLoadAndPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts.toml")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LABCTL_HOSTS", p)
	if Path() != p {
		t.Fatalf("Path() = %q, want %q", Path(), p)
	}
	inv, err := Load(Path())
	if err != nil || len(inv.Hosts) != 3 {
		t.Fatalf("Load: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.toml")); err == nil {
		t.Error("Load of a missing file succeeded")
	}
	t.Setenv("LABCTL_HOSTS", "")
	t.Setenv("HOME", dir)
	if want := filepath.Join(dir, ".config", "labctl", "hosts.toml"); Path() != want {
		t.Errorf("default Path() = %q, want %q", Path(), want)
	}
}
