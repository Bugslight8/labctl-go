package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// load reads the hosts file and, when it names a hub, asks the hub for the host list (merged under the local
// hosts). When the hub does not answer, labctl says so once and works in direct mode from the cached answer plus
// the local hosts. askHub=false skips the hub (commands that never need it, such as off).
func (a *App) load(ctx context.Context, askHub bool) (*view, error) {
	local, err := a.inventory()
	if err != nil {
		return nil, err
	}
	if local.HubHost == "" || a.HubClient == nil {
		return &view{inv: local}, nil
	}
	if !askHub {
		inv, _ := a.fallback(local)
		return &view{inv: inv}, nil
	}
	c := a.HubClient(local.HubHost, local.HubPort)
	resp, err := c.Hosts(ctx)
	if err != nil {
		inv, note := a.fallback(local)
		fmt.Fprintf(a.Stderr, "labctl: hub %s unreachable (%v); direct mode%s\n", local.HubHost, err, note)
		return &view{inv: inv}, nil
	}
	a.saveCache(resp)
	hosts, _ := hubclient.Inventory(resp) // c.Hosts has already refused any unsafe host
	inv := *local
	inv.Hosts, inv.Relay = merge(local.Hosts, hosts), resp.Relay
	return &view{inv: &inv, hub: c, live: resp}, nil
}

func (a *App) saveCache(resp *hub.HostsResponse) {
	if a.CachePath == "" {
		return
	}
	err := sshx.EnsureControlDir(filepath.Dir(a.CachePath))
	if err == nil {
		err = hubclient.SaveCache(a.CachePath, resp)
	}
	if err != nil {
		fmt.Fprintln(a.Stderr, "labctl: caching the hub's host list:", err)
	}
}

// merge puts the local hosts first and adds the other (hub or cached) hosts that collide with none of them by name
// or tailnet name. A local host keeps its own tailnet, user, tmux and mac, so neither a compromised hub nor an edited
// cache can point it at another machine or another login; it only takes HubWakeable from the hub's entry.
func merge(local, other []inventory.Host) []inventory.Host {
	out := append([]inventory.Host(nil), local...)
	collides := func(o inventory.Host) (int, bool) {
		for i, l := range out[:len(local)] {
			if strings.EqualFold(o.Name, l.Name) || strings.EqualFold(o.Tailnet, l.Tailnet) ||
				strings.EqualFold(o.Name, l.Tailnet) || strings.EqualFold(o.Tailnet, l.Name) {
				return i, true
			}
		}
		return 0, false
	}
	for _, o := range other {
		i, hit := collides(o)
		if !hit {
			out = append(out, o)
			continue
		}
		if strings.EqualFold(o.Name, out[i].Name) {
			out[i].HubWakeable = o.HubWakeable
		}
	}
	return out
}

// fallback is the cached hub list merged under the local hosts, and a note for the user on what it used. A cache
// that is missing is normal; one that fails to load (corrupt, or refused by the host rules) is said.
func (a *App) fallback(local *inventory.Inventory) (*inventory.Inventory, string) {
	inv := *local
	if a.CachePath == "" {
		return &inv, ""
	}
	cached, at, err := hubclient.LoadCache(a.CachePath)
	if errors.Is(err, fs.ErrNotExist) {
		return &inv, ""
	}
	if err != nil {
		return &inv, "; ignoring the cached host list: " + err.Error()
	}
	hosts, _ := hubclient.Inventory(cached) // LoadCache has already refused any unsafe host
	inv.Hosts = merge(local.Hosts, hosts)
	if inv.Relay == "" {
		if _, ok := inv.Find(cached.Relay); ok {
			inv.Relay = cached.Relay
		}
	}
	return &inv, ", hosts cached " + ago(time.Now(), at) // file times are wall-clock
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
