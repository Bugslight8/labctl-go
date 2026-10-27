// Package tailnet reads `tailscale status --json` on this machine: which peers exist and which are online.
package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Peer is one tailnet device.
type Peer struct {
	Name     string // first label of the MagicDNS name: what `ssh <name>` resolves
	HostName string // the device's own host name (often DESKTOP-XYZ on Windows)
	OS       string // lowercased: macos, linux, windows, ios, ...
	Online   bool
	LastSeen time.Time // zero while online
	IP       string    // first Tailscale address, IPv4 when there is one
}

// Status is this machine's view of the tailnet.
type Status struct {
	Self  Peer
	Peers []Peer // sorted by Name
}

type rawPeer struct {
	HostName     string
	DNSName      string
	OS           string
	Online       bool
	LastSeen     time.Time
	TailscaleIPs []string
}

type rawStatus struct {
	BackendState string
	Self         rawPeer
	Peer         map[string]rawPeer
}

func (r rawPeer) peer() Peer {
	p := Peer{HostName: r.HostName, OS: strings.ToLower(r.OS), Online: r.Online, LastSeen: r.LastSeen}
	p.Name, _, _ = strings.Cut(strings.TrimSuffix(r.DNSName, "."), ".")
	if p.Name == "" {
		p.Name = strings.ToLower(r.HostName)
	}
	for _, ip := range r.TailscaleIPs {
		if p.IP == "" || (strings.Contains(p.IP, ":") && !strings.Contains(ip, ":")) {
			p.IP = ip
		}
	}
	return p
}

// Parse decodes `tailscale status --json`.
func Parse(r io.Reader) (*Status, error) {
	var raw rawStatus
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	if raw.BackendState != "" && raw.BackendState != "Running" {
		return nil, fmt.Errorf("tailscale is %s on this machine: run `tailscale up`", raw.BackendState)
	}
	s := &Status{Self: raw.Self.peer()}
	for _, rp := range raw.Peer {
		s.Peers = append(s.Peers, rp.peer())
	}
	sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].Name < s.Peers[j].Name })
	return s, nil
}

// Lookup finds a peer by MagicDNS name (short or full) or by its own host name, ignoring case.
func (s *Status) Lookup(q string) (Peer, bool) {
	short, _, _ := strings.Cut(strings.TrimSuffix(q, "."), ".")
	for _, p := range s.Peers {
		if strings.EqualFold(p.Name, short) {
			return p, true
		}
	}
	// a host name is chosen by the device itself, so it only counts when no MagicDNS name matched
	for _, p := range s.Peers {
		if strings.EqualFold(p.HostName, q) {
			return p, true
		}
	}
	return Peer{}, false
}

// macApp is where the Mac App Store and standalone Tailscale apps keep their CLI.
const macApp = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"

// Query runs `tailscale status --json` on this machine.
func Query(ctx context.Context) (*Status, error) {
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		if _, statErr := os.Stat(macApp); statErr != nil {
			return nil, fmt.Errorf("tailscale CLI not found: install Tailscale and sign in")
		}
		bin = macApp
	}
	out, err := exec.CommandContext(ctx, bin, "status", "--json").Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("tailscale status: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("tailscale status: %w", err)
	}
	return Parse(strings.NewReader(string(out)))
}
