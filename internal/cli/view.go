package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/hubclient"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/sshx"
)

// HubAPI is the hub as the CLI uses it: hubclient.Client on a real device.
type HubAPI interface {
	Hosts(ctx context.Context) (*hub.HostsResponse, error)
	Events(ctx context.Context, since uint64, boot string) (*hub.EventsResponse, error)
	Wake(ctx context.Context, name string) error
}

// view is what one command works from: the hosts, and the hub when it answered.
type view struct {
	inv  *inventory.Inventory
	hub  HubAPI             // nil in direct mode
	live *hub.HostsResponse // the hub's answer, when it answered
}

// load reads the hosts file and, when it names a hub, asks the hub for the host list. The hub's list wins; when
// the hub does not answer, labctl says so once and works in direct mode from the cached answer plus the local
// hosts. askHub=false skips the hub (commands that never need it, such as off).
func (a *App) load(ctx context.Context, askHub bool) (*view, error) {
	local, err := a.inventory()
	if err != nil {
		return nil, err
	}
	if local.HubHost == "" || a.HubClient == nil {
		return &view{inv: local}, nil
	}
	if askHub {
		c := a.HubClient(local.HubHost, local.HubPort)
		resp, err := c.Hosts(ctx)
		if err == nil {
			hosts, _ := hubclient.Inventory(resp) // Hosts has already checked every host
			if a.CachePath != "" && sshx.EnsureControlDir(filepath.Dir(a.CachePath)) == nil {
				if err := hubclient.SaveCache(a.CachePath, resp); err != nil {
					fmt.Fprintln(a.Stderr, "labctl: caching the hub's host list:", err)
				}
			}
			inv := *local
			inv.Hosts, inv.Relay = hosts, resp.Relay
			return &view{inv: &inv, hub: c, live: resp}, nil
		}
		defer func(err error) {
			fmt.Fprintf(a.Stderr, "labctl: hub %s unreachable (%v); direct mode%s\n", local.HubHost, err, a.cacheNote())
		}(err)
	}
	return &view{inv: a.fallback(local)}, nil
}

// fallback is the cached hub list with the local hosts on top (a local entry, which may carry a mac, replaces the
// cached one of the same name).
func (a *App) fallback(local *inventory.Inventory) *inventory.Inventory {
	inv := *local
	cached, _, err := hubclient.LoadCache(a.CachePath)
	if err != nil {
		return &inv
	}
	hosts, _ := hubclient.Inventory(cached)
	inv.Hosts = nil
	for _, h := range hosts {
		if _, ok := local.Find(h.Name); !ok {
			inv.Hosts = append(inv.Hosts, h)
		}
	}
	inv.Hosts = append(inv.Hosts, local.Hosts...)
	if inv.Relay == "" {
		if _, ok := inv.Find(cached.Relay); ok {
			inv.Relay = cached.Relay
		}
	}
	return &inv
}

func (a *App) cacheNote() string {
	if a.CachePath == "" {
		return ""
	}
	if _, at, err := hubclient.LoadCache(a.CachePath); err == nil {
		return ", hosts cached " + ago(time.Now(), at) // file times are wall-clock
	}
	return ""
}

// lsHub prints the hub's view: its state, and since when.
func (a *App) lsHub(v *view) error {
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tOS\tADDRESS\tSINCE\t")
	for _, h := range v.live.Hosts {
		note := ""
		switch {
		case strings.EqualFold(h.Name, v.live.Relay):
			note = "relay"
		case h.Wakeable && h.State != string(hub.Up):
			note = "wakeable"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Name, printable(h.State), printable(h.OS), printable(h.IP), ago(a.Now(), h.Since), note)
	}
	return tw.Flush()
}
