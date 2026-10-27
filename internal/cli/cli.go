// Package cli is labctl's command line: it maps arguments to actions on the inventory, the tailnet and ssh.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/sshx"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

// Version is set by main.
var Version = "dev"

// App holds everything a command touches, so tests can swap each piece for a fake.
type App struct {
	Stdout, Stderr io.Writer
	HostsPath      string
	Status         func(context.Context) (*tailnet.Status, error)
	Now            func() time.Time
	ControlDir     string                                                // where the shared SSH connection sockets live
	Exec           func(ctx context.Context, argv []string) (int, error) // runs ssh with this terminal; returns its exit code
	Sleep          func(time.Duration)                                   // waits between tailnet polls while a host wakes
	SendWOL        func(mac net.HardwareAddr, addr string) error         // sends a magic packet from this machine
}

const usage = `labctl - command center for the home lab

  labctl                      same as labctl ls
  labctl ls                   every host: up / asleep, OS, Tailscale address, last seen
  labctl hosts init           write the hosts file from your tailnet (then add mac = ... to wake a host)
  labctl wake <host>          wake a host through the relay and wait until it is online (--no-wait: do not wait)
  labctl wol <mac>            send a Wake-on-LAN packet from this machine (the relay runs this)
  labctl <host>               shell on the host, in its tmux session (wakes it first when it is asleep)
  labctl <host> <cmd...>      run a command there; one quoted argument runs as a shell string
  labctl off [host]           close the shared SSH connections
  labctl version
`

// Run executes one command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if err := a.run(ctx, args); err != nil {
		var ec exitCode
		if errors.As(err, &ec) {
			return int(ec)
		}
		fmt.Fprintln(a.Stderr, "labctl:", err)
		return 1
	}
	return 0
}

// exitCode passes a remote command's exit status through without printing anything.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func (a *App) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return a.ls(ctx)
	}
	switch args[0] {
	case "ls":
		return a.ls(ctx)
	case "hosts":
		if len(args) == 2 && args[1] == "init" {
			return a.hostsInit(ctx)
		}
		return errors.New("usage: labctl hosts init")
	case "version", "--version":
		fmt.Fprintln(a.Stdout, "labctl", Version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
		return nil
	case "off":
		return a.off(ctx, args[1:])
	case "wake":
		return a.wakeCmd(ctx, args[1:])
	case "wol":
		return a.wolCmd(args[1:])
	}
	return a.onHost(ctx, args[0], args[1:])
}

// onHost opens a shell on the host (no cmd) or runs cmd there, passing its exit code through.
func (a *App) onHost(ctx context.Context, name string, cmd []string) error {
	inv, err := a.inventory()
	if err != nil {
		return err
	}
	h, ok := inv.Find(name)
	if !ok {
		return fmt.Errorf("unknown command or host %q (labctl help; hosts are in %s)", name, a.HostsPath)
	}
	if err := a.autoWake(ctx, inv, h); err != nil {
		return err
	}
	if err := sshx.EnsureControlDir(a.ControlDir); err != nil {
		return err
	}
	argv := sshx.Argv(h, a.ControlDir, sshx.ShellCommand(h), true)
	if len(cmd) > 0 {
		argv = sshx.Argv(h, a.ControlDir, sshx.RemoteCommand(cmd), false)
	}
	return a.exec(ctx, argv)
}

func (a *App) exec(ctx context.Context, argv []string) error {
	code, err := a.Exec(ctx, argv)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// off closes the shared connection of one host, or of every host. A host with no open connection is not an error.
func (a *App) off(ctx context.Context, names []string) error {
	inv, err := a.inventory()
	if err != nil {
		return err
	}
	hosts := inv.Hosts
	if len(names) > 0 {
		hosts = nil
		for _, n := range names {
			h, ok := inv.Find(n)
			if !ok {
				return fmt.Errorf("unknown host %q", n)
			}
			hosts = append(hosts, h)
		}
	}
	for _, h := range hosts {
		code, err := a.Exec(ctx, sshx.OffArgv(h, a.ControlDir))
		if err != nil {
			return err
		}
		if code == 0 { // 255 = no shared connection open: nothing to close
			fmt.Fprintf(a.Stdout, "closed %s\n", h.Name)
		}
	}
	return nil
}

func (a *App) inventory() (*inventory.Inventory, error) {
	inv, err := inventory.Load(a.HostsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no hosts file at %s: run `labctl hosts init`", a.HostsPath)
	}
	return inv, err
}

func (a *App) ls(ctx context.Context) error {
	inv, err := a.inventory()
	if err != nil {
		return err
	}
	st, err := a.Status(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tOS\tADDRESS\tLAST SEEN\t")
	listed := map[string]bool{}
	for _, h := range inv.Hosts {
		p, ok := st.Lookup(h.Tailnet)
		if !ok {
			fmt.Fprintf(tw, "%s\tnot-on-tailnet\t-\t-\t-\t\n", h.Name)
			continue
		}
		listed[p.Name] = true
		state, seen := "asleep", ago(a.Now(), p.LastSeen)
		if p.Online {
			state, seen = "up", "now"
		}
		note := ""
		switch {
		case strings.EqualFold(h.Name, inv.Relay):
			note = "relay"
		case !p.Online && h.MAC != "" && inv.Relay != "":
			note = "wakeable"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Name, state, printable(p.OS), printable(p.IP), seen, note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	var extra []string
	for _, p := range st.Peers {
		if !listed[p.Name] {
			extra = append(extra, printable(p.Name))
		}
	}
	if len(extra) > 0 {
		fmt.Fprintf(a.Stdout, "\non the tailnet, not in the hosts file: %s\n", strings.Join(extra, ", "))
	}
	return nil
}

// printable replaces control characters in what other tailnet devices report about themselves, so a peer cannot
// send escape sequences to this terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// ago is a short human age: 45s ago, 12m ago, 3h ago, 2d ago; "-" when unknown.
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func (a *App) hostsInit(ctx context.Context) error {
	if _, err := os.Stat(a.HostsPath); err == nil {
		return fmt.Errorf("%s already exists: edit it, or move it away first", a.HostsPath)
	}
	st, err := a.Status(ctx)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# labctl hosts file. Written by `labctl hosts init`; edit freely.\n")
	b.WriteString("# relay: the always-on host that sends Wake-on-LAN packets (it needs labctl installed).\n")
	b.WriteString("# relay = \"mini\"\n")
	peers := append([]tailnet.Peer(nil), st.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	n, written := 0, map[string]bool{}
	for _, p := range peers {
		if written[strings.ToLower(p.Name)] { // e.g. a node shared in from another tailnet with the same first label
			fmt.Fprintf(a.Stderr, "skipped tailnet peer %q: a host with that name is already written\n", printable(p.Name))
			continue
		}
		block := fmt.Sprintf("\n[[host]]\nname = %q\nos = %q\n# user = \"\"            # ssh login; default: ~/.ssh/config, then your local user\n# mac = \"\"             # Ethernet MAC, so the relay can wake this host\n# tmux = \"main\"        # session to attach; \"\" = plain shell\n", p.Name, p.OS)
		if _, err := inventory.Parse([]byte(block)); err != nil {
			fmt.Fprintf(a.Stderr, "skipped tailnet peer %q: %v\n", p.Name, err)
			continue
		}
		b.WriteString(block)
		written[strings.ToLower(p.Name)] = true
		n++
	}
	if err := os.MkdirAll(filepath.Dir(a.HostsPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(a.HostsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "wrote %d hosts to %s\nnext: set relay, and mac = ... for each host to wake\n", n, a.HostsPath)
	return nil
}
