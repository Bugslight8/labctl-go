// Command labctl is the command center for the home lab.
package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bugslight8/labctl/internal/cli"
	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
	"github.com/Bugslight8/labctl/internal/wol"
)

const version = "0.1.0-dev"

func main() {
	cli.Version = version
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
	}
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
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
