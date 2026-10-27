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
	DNSName  string // full MagicDNS name without the trailing dot; peers shared in from another tailnet differ here
	HostName string // the device's own host name (often DESKTOP-XYZ on Windows)
	OS       string // lowercased: macos, linux, windows, ios, ...
	Online   bool
	LastSeen time.Time // zero while online
	IP       string    // first Tailscale address, IPv4 when there is one
}

// Status is this machine's view of the tailnet.
type Status struct {
	Self   Peer
	Peers  []Peer // sorted by Name, then DNSName
	Suffix string // this tailnet's MagicDNS suffix, e.g. tail0000.ts.net
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
	BackendState   string
	MagicDNSSuffix string
	Self           rawPeer
	Peer           map[string]rawPeer
}

func (r rawPeer) peer() Peer {
	p := Peer{HostName: r.HostName, OS: strings.ToLower(r.OS), Online: r.Online, LastSeen: r.LastSeen}
	p.DNSName = strings.TrimSuffix(r.DNSName, ".")
	p.Name, _, _ = strings.Cut(p.DNSName, ".")
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
	s := &Status{Self: raw.Self.peer(), Suffix: strings.Trim(raw.MagicDNSSuffix, ".")}
	for _, rp := range raw.Peer {
		s.Peers = append(s.Peers, rp.peer())
	}
	sortPeers(s.Peers)
	return s, nil
}

// sortPeers orders by Name, then full DNSName, so equal first labels never depend on JSON map order.
func sortPeers(ps []Peer) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].DNSName < ps[j].DNSName
	})
}

// Lookup finds a peer by full MagicDNS name, by short name (preferring this tailnet's node over ones shared in
// from other tailnets), or by its own host name, ignoring case.
func (s *Status) Lookup(q string) (Peer, bool) {
	full := strings.TrimSuffix(q, ".")
	short, _, dotted := strings.Cut(full, ".")
	if dotted {
		for _, p := range s.Peers {
			if strings.EqualFold(p.DNSName, full) {
				return p, true
			}
		}
	}
	var first *Peer
	for i, p := range s.Peers {
		if !strings.EqualFold(p.Name, short) {
			continue
		}
		if s.Suffix != "" && strings.EqualFold(p.DNSName, p.Name+"."+s.Suffix) {
			return p, true
		}
		if first == nil {
			first = &s.Peers[i]
		}
	}
	if first != nil {
		return *first, true
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

// Binary is the tailscale CLI on this machine: on PATH, else inside the macOS app.
func Binary() (string, error) {
	if bin, err := exec.LookPath("tailscale"); err == nil {
		return bin, nil
	}
	if _, err := os.Stat(macApp); err != nil {
		return "", fmt.Errorf("tailscale CLI not found: install Tailscale and sign in")
	}
	return macApp, nil
}

// Query runs `tailscale status --json` on this machine.
func Query(ctx context.Context) (*Status, error) {
	bin, err := Binary()
	if err != nil {
		return nil, err
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
