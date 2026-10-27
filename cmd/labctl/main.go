// Command labctl is the command center for the home lab.
package main

import (
	"context"
	"os"
	"time"

	"github.com/Bugslight8/labctl/internal/cli"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
)

const version = "0.1.0-dev"

func main() {
	cli.Version = version
	app := &cli.App{
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		HostsPath: inventory.Path(),
		Status:    tailnet.Query,
		Now:       time.Now,
	}
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
