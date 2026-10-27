package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/sshx"
	"github.com/Bugslight8/labctl/internal/tailnet"
	"github.com/Bugslight8/labctl/internal/wol"
)

const (
	wakePoll       = 2 * time.Second
	wakeTimeout    = 120 * time.Second
	wakePollErrors = 3 // consecutive tailscale failures before giving up: the problem is here, not on the host
)

// relayPath finds labctl on the relay in a non-interactive ssh session, where ~/.local/bin is often not on PATH.
const relayPath = `PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH" `

// wakeCmd: labctl wake <host> [--no-wait]
func (a *App) wakeCmd(ctx context.Context, args []string) error {
	var name string
	wait := true
	for _, arg := range args {
		switch {
		case arg == "--no-wait":
			wait = false
		case name == "" && !strings.HasPrefix(arg, "-"):
			name = arg
		default:
			return errors.New("usage: labctl wake <host> [--no-wait]")
		}
	}
	if name == "" {
		return errors.New("usage: labctl wake <host> [--no-wait]")
	}
	inv, err := a.inventory()
	if err != nil {
		return err
	}
	h, ok := inv.Find(name)
	if !ok {
		return fmt.Errorf("unknown host %q", name)
	}
	st, err := a.Status(ctx)
	if err != nil {
		return err
	}
	return a.wake(ctx, inv, h, st, wait)
}

// wake asks the relay to send h's magic packet, then (when wait) polls the tailnet until h is online.
// Progress goes to Stderr: before an auto-woken command, Stdout belongs to that command's output.
func (a *App) wake(ctx context.Context, inv *inventory.Inventory, h inventory.Host, st *tailnet.Status, wait bool) error {
	if h.MAC == "" {
		return fmt.Errorf("%s has no mac in %s, so it cannot be woken", h.Name, a.HostsPath)
	}
	if inv.Relay == "" {
		return fmt.Errorf("no relay in %s: set relay = \"<always-on host>\"", a.HostsPath)
	}
	p, onTailnet := st.Lookup(h.Tailnet)
	if onTailnet && p.Online {
		fmt.Fprintf(a.Stdout, "%s is already up\n", h.Name)
		return nil
	}
	relay, _ := inv.Find(inv.Relay)
	if p, ok := st.Lookup(relay.Tailnet); !ok || !p.Online {
		return fmt.Errorf("the relay %s is not online, so nothing can send the wake packet", relay.Name)
	}
	if err := sshx.EnsureControlDir(a.ControlDir); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "waking %s via %s ...\n", h.Name, relay.Name)
	// -n: the relay must not read the user's stdin (it may be piped into the command that follows);
	// >&2: the relay's own output must not land in the user's stdout
	argv := sshx.Argv(relay, a.ControlDir, relayPath+"labctl wol "+sshx.Quote([]string{h.MAC})+" >&2", false)
	argv = append([]string{argv[0], "-n"}, argv[1:]...)
	code, err := a.Exec(ctx, argv)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the relay %s could not send the wake packet (exit %d): is labctl installed there?", relay.Name, code)
	}
	if !wait {
		return nil
	}
	if !onTailnet {
		fmt.Fprintf(a.Stderr, "sent; %s is not on the tailnet, so labctl cannot tell when it is up\n", h.Name)
		return nil
	}
	start, failures := a.Now(), 0
	for a.Now().Sub(start) < wakeTimeout {
		a.Sleep(wakePoll)
		st, err := a.Status(ctx)
		if err != nil {
			if failures++; failures >= wakePollErrors {
				return fmt.Errorf("checking whether %s woke: %w", h.Name, err)
			}
			continue
		}
		failures = 0
		if p, ok := st.Lookup(h.Tailnet); ok && p.Online {
			fmt.Fprintf(a.Stderr, "%s is up (%ds)\n", h.Name, int(a.Now().Sub(start).Seconds()))
			return nil
		}
	}
	return fmt.Errorf("%s did not come online within %d s. Check Wake-on-LAN on it: enabled in the firmware and on the "+
		"network adapter, connected by Ethernet (Wi-Fi rarely wakes), and mac = %s is its Ethernet MAC",
		h.Name, int(wakeTimeout.Seconds()), h.MAC)
}

// autoWake wakes h before a shell or command when the tailnet says it is asleep. Anything it cannot decide
// (tailscale unavailable, host unknown to the tailnet) falls through to ssh, which gives its own error.
func (a *App) autoWake(ctx context.Context, inv *inventory.Inventory, h inventory.Host) error {
	st, err := a.Status(ctx)
	if err != nil {
		return nil
	}
	p, ok := st.Lookup(h.Tailnet)
	if !ok || p.Online {
		return nil
	}
	reason := ""
	switch {
	case strings.EqualFold(h.Name, inv.Relay):
		reason = "it is the relay itself; nothing else can send its wake packet"
	case h.MAC == "":
		reason = "no mac for it in the hosts file"
	case inv.Relay == "":
		reason = "no relay in the hosts file"
	}
	if reason != "" {
		fmt.Fprintf(a.Stderr, "%s looks asleep (last seen %s) and cannot be woken (%s); trying anyway\n",
			h.Name, ago(a.Now(), p.LastSeen), reason)
		return nil
	}
	return a.wake(ctx, inv, h, st, true)
}

// wolCmd: labctl wol <mac> [--to host:port] sends the magic packet from this machine.
func (a *App) wolCmd(args []string) error {
	addr := wol.Broadcast
	if len(args) == 3 && args[1] == "--to" {
		addr, args = args[2], args[:1]
	}
	if len(args) != 1 {
		return errors.New("usage: labctl wol <mac> [--to host:port]")
	}
	mac, err := net.ParseMAC(args[0])
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("%q is not a 6-byte MAC address", args[0])
	}
	if err := a.SendWOL(mac, addr); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "sent Wake-on-LAN for %s to %s\n", mac, addr)
	return nil
}
