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

func TestRelayByTailnetName(t *testing.T) {
	inv, err := Parse([]byte("relay = \"m1\"\n[[host]]\nname = \"mini\"\ntailnet = \"m1\"\n"))
	if err != nil || inv.Relay != "mini" {
		t.Errorf("relay = %q (%v), want the host name mini", inv.Relay, err)
	}
}

func TestHubTable(t *testing.T) {
	inv, err := Parse([]byte("[hub]\nallow = [\"me@example.com\"]\n[[host]]\nname = \"a\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hub == nil || len(inv.Hub.Allow) != 1 || inv.Hub.Allow[0] != "me@example.com" || inv.Hub.Port != DefaultHubPort {
		t.Fatalf("hub = %+v", inv.Hub)
	}
	if inv, _ := Parse([]byte("[[host]]\nname = \"a\"\n")); inv.Hub != nil {
		t.Error("no [hub] table must mean Hub == nil")
	}
	inv, err = Parse([]byte("[hub]\nallow = [\"me@github\", \"Spouse@Example.com\"]\nport = 8000\n"))
	if err != nil || inv.Hub.Port != 8000 || inv.Hub.Allow[1] != "spouse@example.com" {
		t.Errorf("port/allow: %+v %v (logins compare lowercased)", inv.Hub, err)
	}
	for what, src := range map[string]string{
		"empty allow": "[hub]\nallow = []\n",
		"no allow":    "[hub]\nport = 7300\n",
		"bad login":   "[hub]\nallow = [\"not a login\"]\n",
		"star":        "[hub]\nallow = [\"*\"]\n",
		"port 0":      "[hub]\nallow = [\"me@x.com\"]\nport = 0\n",
		"port big":    "[hub]\nallow = [\"me@x.com\"]\nport = 70000\n",
		"unknown key": "[hub]\nallow = [\"me@x.com\"]\nopen = true\n",
	} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

func TestHubHost(t *testing.T) {
	inv, err := Parse([]byte("hub_host = \"mini\"\n"))
	if err != nil || inv.HubHost != "mini" || inv.HubPort != DefaultHubPort || len(inv.Hosts) != 0 {
		t.Fatalf("client file: %+v %v", inv, err)
	}
	inv, err = Parse([]byte("hub_host = \"mini.tail0000.ts.net\"\nhub_port = 8000\n"))
	if err != nil || inv.HubPort != 8000 {
		t.Errorf("full name and port: %+v %v", inv, err)
	}
	for _, bad := range []string{"hub_host = \"-oProxyCommand=x\"\n", "hub_host = \"a b\"\n", "hub_host = \"mini\"\nhub_port = 0\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// CheckHost is the rule Parse applies to each host; the hub client applies it to every host the hub sends.
func TestCheckHost(t *testing.T) {
	ok := Host{Name: "korg", Tailnet: "korg", User: "krish", Tmux: "main"}
	if err := CheckHost(ok); err != nil {
		t.Errorf("valid host: %v", err)
	}
	for _, h := range []Host{
		{Name: "-oProxyCommand=x", Tailnet: "a"},
		{Name: "a", Tailnet: "-oX"},
		{Name: "a", Tailnet: "a", User: "root@evil"},
		{Name: "a", Tailnet: "a", Tmux: "x;reboot"},
		{Name: "", Tailnet: "a"},
	} {
		if err := CheckHost(h); err == nil {
			t.Errorf("%+v accepted", h)
		}
	}
}
