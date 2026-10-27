package cli

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	watchHistory = 10 // events of history shown when watch starts
	watchRetry   = 2 * time.Second
)

// watch prints the hub's events as they happen, until ctx ends (Ctrl-C). A hub that stops answering is reported
// once per outage and retried; a hub restart (new boot id) is announced and followed from its first event.
func (a *App) watch(ctx context.Context) error {
	local, err := a.inventory()
	if err != nil {
		return err
	}
	if local.HubHost == "" || a.HubClient == nil {
		return errors.New("labctl watch needs a hub: set hub_host = \"<the hub's MagicDNS name>\" in the hosts file")
	}
	h := a.HubClient(local.HubHost, local.HubPort)
	var since uint64
	boot, first, failing := "", true, false
	for {
		r, err := h.Events(ctx, since, boot)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if !failing {
				fmt.Fprintf(a.Stderr, "labctl: hub: %v; retrying\n", err)
				failing = true
			}
			a.Sleep(watchRetry)
			continue
		}
		if failing {
			fmt.Fprintln(a.Stderr, "labctl: hub back")
			failing = false
		}
		if boot != "" && r.Boot != boot {
			fmt.Fprintln(a.Stderr, "labctl: hub restarted; following it from its first event")
		}
		events := r.Events
		if first && len(events) > watchHistory {
			events = events[len(events)-watchHistory:]
		}
		first = false
		for _, e := range events {
			from := e.From
			if from == "" {
				from = "(start)"
			}
			fmt.Fprintf(a.Stdout, "%s  %-16s %s -> %s\n", e.Time.Local().Format("15:04:05"), printable(e.Host), printable(from), printable(e.To))
		}
		since, boot = r.Last, r.Boot
	}
}
