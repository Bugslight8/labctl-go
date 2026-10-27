package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

// Options are everything Serve touches, so the end-to-end test can swap each for a fake.
type Options struct {
	HostsPath string
	StateDir  string
	Stderr    io.Writer
	Status    func(context.Context) (*tailnet.Status, error)
	Whois     Whois
	IPs       func(context.Context) ([]string, error) // this machine's Tailscale addresses
	Dial      func(ctx context.Context, addr string) error
	SendWOL   func(mac net.HardwareAddr, addr string) error
	Now       func() time.Time
	Listen    func(network, addr string) (net.Listener, error)
	PollEvery time.Duration
	LongPoll  time.Duration
	Ready     func(addrs []string) // called once every listener is up; may be nil
}

// Serve runs the hub until ctx ends: it refuses to start without a [hub] table with an allow list, or without a
// Tailscale address to listen on.
func Serve(ctx context.Context, o Options) error {
	inv, err := inventory.Load(o.HostsPath)
	if err != nil {
		return err
	}
	if inv.Hub == nil {
		return fmt.Errorf("%s has no [hub] table: add\n  [hub]\n  allow = [\"<your Tailscale login>\"]", o.HostsPath)
	}
	ips, err := o.IPs(ctx)
	if err != nil {
		return err
	}
	addrs, err := ListenAddrs(ips, inv.Hub.Port)
	if err != nil {
		return err
	}
	st, err := o.Status(ctx) // the hub's own MagicDNS names, which clients put in the Host header
	if err != nil {
		return err
	}
	allowedHosts := append([]string{st.Self.Name, st.Self.DNSName}, ips...)
	audit, err := OpenAudit(o.StateDir, o.Now)
	if err != nil {
		return err
	}
	defer audit.Close()
	logf := func(format string, args ...any) {
		fmt.Fprintf(o.Stderr, "%s labctl hub: %s\n", o.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}

	mon := NewMonitor(inv, o.Status, o.Dial, o.Now)
	auth := NewAuthorizer(inv.Hub.Allow, o.Whois, o.Now)
	auth.RefuseFrom(ips)
	srv := &Server{Inv: inv, Mon: mon, Auth: auth, Audit: audit, SendWOL: o.SendWOL, Now: o.Now,
		LongPoll: o.LongPoll, AllowedHosts: allowedHosts}
	handler := srv.Handler()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var servers []*http.Server
	errc := make(chan error, len(addrs))
	for _, addr := range addrs {
		ln, err := o.Listen("tcp", addr)
		if err != nil {
			for _, hs := range servers {
				_ = hs.Close()
			}
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		hs := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
			WriteTimeout: o.LongPoll + 10*time.Second, IdleTimeout: 60 * time.Second,
			// requests inherit ctx, so a waiting long poll ends as soon as the hub stops
			BaseContext: func(net.Listener) context.Context { return ctx }}
		servers = append(servers, hs)
		go func() {
			if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	go mon.Run(ctx, o.PollEvery, logf)
	logf("listening on %s; allowed: %s", strings.Join(addrs, ", "), strings.Join(inv.Hub.Allow, ", "))
	if o.Ready != nil {
		o.Ready(addrs)
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	cancel() // ends long polls and the monitor on an errc exit too
	// a short grace period, then force: Shutdown alone waits up to 5 s for a connection that never sent a request
	shut, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	for _, hs := range servers {
		if hs.Shutdown(shut) != nil {
			_ = hs.Close()
		}
	}
	return err
}

// Main is `labctl hub [serve|install|uninstall]`.
func Main(ctx context.Context, args []string, o Options, l *Launchd, stdout io.Writer) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "serve":
		return Serve(ctx, o)
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		hosts, err := filepath.Abs(o.HostsPath)
		if err != nil {
			return err
		}
		msg, err := l.Install(exe, hosts, o.StateDir)
		if err == nil {
			fmt.Fprintln(stdout, msg)
		}
		return err
	case "uninstall":
		if err := l.Uninstall(); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "removed the hub's launchd job")
		return nil
	}
	return errors.New("usage: labctl hub [serve|install|uninstall]")
}
