// Command labctl is the command center for the home lab.
package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Bugslight8/labctl/internal/cli"
	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/hubclient"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
	"github.com/Bugslight8/labctl/internal/wol"
)

const version = "0.2.0-dev"

func main() {
	cli.Version = version
	os.Exit(newApp(hubclient.SystemDialer().DialContext).Run(context.Background(), os.Args[1:]))
}

// newApp is the real wiring. hubDial opens connections to the hub; only the end-to-end test swaps it.
func newApp(hubDial func(ctx context.Context, network, addr string) (net.Conn, error)) *cli.App {
	app := &cli.App{
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		HostsPath:  inventory.Path(),
		Status:     tailnet.Query,
		Now:        time.Now,
		ControlDir: cli.DefaultControlDir(),
		Exec:       cli.SystemExec,
		Sleep:      time.Sleep,
		SendWOL:    wol.Send,
		HubClient: func(host string, port int) cli.HubAPI {
			return hubclient.New(host, port, hubDial)
		},
	}
	app.CachePath = filepath.Join(app.ControlDir, "hosts.json")
	app.Hub = func(ctx context.Context, args []string) error {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return hub.Main(ctx, args, hub.Options{
			HostsPath: app.HostsPath,
			StateDir:  hub.StateDir(),
			Stderr:    os.Stderr,
			Status:    tailnet.Query,
			Whois:     hub.TailscaleWhois,
			IPs:       hub.TailscaleIPs,
			Dial:      hub.DialTCP,
			SendWOL:   wol.Send,
			Now:       time.Now,
			Listen:    net.Listen,
			PollEvery: 5 * time.Second,
			LongPoll:  25 * time.Second,
		}, hub.NewLaunchd(), os.Stdout)
	}
	return app
}
