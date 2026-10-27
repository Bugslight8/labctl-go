// Package inventory loads the hosts file: every machine labctl can reach, and the relay that wakes them.
package inventory

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultTmux is the tmux session a shell attaches to when the hosts file does not name one.
const DefaultTmux = "main"

// DefaultHubPort is where the hub listens on its Tailscale addresses.
const DefaultHubPort = 7300

// Host is one machine. Every string field here reaches an ssh argv or a remote command, so Parse validates it.
type Host struct {
	Name    string // what the user types: labctl <name>
	Tailnet string // MagicDNS host name; defaults to Name
	User    string // ssh login; empty = ssh's default (~/.ssh/config, then the local user)
	OS      string // informational: macos, linux, windows
	MAC     string // canonical aa:bb:cc:dd:ee:ff, or empty when the host cannot be woken
	Tmux    string // session to attach; empty = a plain login shell
}

// Inventory is the parsed hosts file.
type Inventory struct {
	Relay string // name of the host that sends wake packets; empty = no waking
	Hosts []Host
	Hub   *Hub // the [hub] table: only the hub's own hosts file has one
}

// Hub configures `labctl hub`.
type Hub struct {
	Allow []string // Tailscale logins (lowercased) that may use the hub; never empty
	Port  int
}

type file struct {
	Relay string    `toml:"relay"`
	Host  []rawHost `toml:"host"`
	Hub   *rawHub   `toml:"hub"`
}

type rawHub struct {
	Allow []string `toml:"allow"`
	Port  *int     `toml:"port"`
}

// login is a Tailscale login name: user@domain, or user@github style for GitHub sign-ins. No wildcards.
var login = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$`)

type rawHost struct {
	Name    string  `toml:"name"`
	Tailnet string  `toml:"tailnet"`
	User    string  `toml:"user"`
	OS      string  `toml:"os"`
	MAC     string  `toml:"mac"`
	Tmux    *string `toml:"tmux"` // nil = default session, "" = plain shell
}

// safe is the only shape a name, tailnet, user or tmux session may have: it cannot start with '-' (an ssh option)
// and holds no shell or ssh metacharacters (space, ';', '$', '@', quotes).
var safe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Path is $LABCTL_HOSTS, else ~/.config/labctl/hosts.toml.
func Path() string {
	if p := os.Getenv("LABCTL_HOSTS"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "labctl", "hosts.toml")
}

// Load reads and validates the hosts file at path.
func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inv, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

// Parse validates a hosts file. Unknown keys are errors, so a typo never silently drops a setting.
func Parse(data []byte) (*Inventory, error) {
	var f file
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&f)
	if err != nil {
		return nil, err
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		return nil, fmt.Errorf("unknown key %q", extra[0].String())
	}
	inv := &Inventory{Relay: f.Relay}
	if f.Hub != nil {
		hub, err := parseHub(f.Hub)
		if err != nil {
			return nil, err
		}
		inv.Hub = hub
	}
	seen := map[string]bool{}
	for i, r := range f.Host {
		h := Host{Name: r.Name, Tailnet: r.Tailnet, User: r.User, OS: strings.ToLower(r.OS), Tmux: DefaultTmux}
		if h.Tailnet == "" {
			h.Tailnet = h.Name
		}
		if r.Tmux != nil {
			h.Tmux = *r.Tmux
		}
		fields := [][2]string{{"name", h.Name}, {"tailnet", h.Tailnet}}
		if h.User != "" {
			fields = append(fields, [2]string{"user", h.User})
		}
		if h.Tmux != "" {
			fields = append(fields, [2]string{"tmux", h.Tmux})
		}
		for _, f := range fields {
			if !safe.MatchString(f[1]) {
				return nil, fmt.Errorf("host %d: %s %q: use letters, digits, '.', '_' or '-', not starting with '-' or '.'", i+1, f[0], f[1])
			}
		}
		if r.MAC != "" {
			hw, err := net.ParseMAC(r.MAC)
			if err != nil || len(hw) != 6 {
				return nil, fmt.Errorf("host %q: mac %q is not a 6-byte MAC address", h.Name, r.MAC)
			}
			h.MAC = hw.String()
		}
		key := strings.ToLower(h.Name)
		if seen[key] {
			return nil, fmt.Errorf("host %q is listed twice", h.Name)
		}
		seen[key] = true
		inv.Hosts = append(inv.Hosts, h)
	}
	if inv.Relay != "" {
		r, ok := inv.Find(inv.Relay)
		if !ok {
			return nil, fmt.Errorf("relay %q is not a host in this file", inv.Relay)
		}
		inv.Relay = r.Name // callers compare host names
	}
	return inv, nil
}

func parseHub(r *rawHub) (*Hub, error) {
	if len(r.Allow) == 0 {
		return nil, fmt.Errorf("[hub] allow is empty: list the Tailscale logins that may use the hub")
	}
	h := &Hub{Port: DefaultHubPort}
	for _, l := range r.Allow {
		if !login.MatchString(l) {
			return nil, fmt.Errorf("[hub] allow: %q is not a Tailscale login (user@domain)", l)
		}
		h.Allow = append(h.Allow, strings.ToLower(l))
	}
	if r.Port != nil {
		if *r.Port < 1 || *r.Port > 65535 {
			return nil, fmt.Errorf("[hub] port %d is not 1-65535", *r.Port)
		}
		h.Port = *r.Port
	}
	return h, nil
}

// Find returns the host whose name or tailnet name is q, ignoring case.
func (inv *Inventory) Find(q string) (Host, bool) {
	for _, h := range inv.Hosts {
		if strings.EqualFold(h.Name, q) || strings.EqualFold(h.Tailnet, q) {
			return h, true
		}
	}
	return Host{}, false
}
