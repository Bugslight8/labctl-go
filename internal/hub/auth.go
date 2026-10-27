package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Bugslight8/labctl/internal/tailnet"
)

const (
	whoisTTL     = 10 * time.Second // short: Tailscale can hand an address to another device
	whoisFailTTL = 5 * time.Second  // failed lookups are cached too, so a stranger cannot make one per request
	whoisMax     = 4                // concurrent `tailscale whois` processes, across all addresses
	whoisTimeout = 5 * time.Second
)

// Tailscale assigns addresses only from these ranges; the hub trusts whois answers only for them.
var tailnetRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// InTailnet reports whether a is in the ranges Tailscale assigns addresses from.
func InTailnet(a netip.Addr) bool {
	for _, p := range tailnetRanges {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// Caller is who is on the other end of a request, according to this machine's Tailscale.
type Caller struct {
	Login  string // lowercased Tailscale login, e.g. owner@example.com
	Device string
	Addr   string
	Tagged bool // a tagged device (a server identity), never a person
}

// Whois asks Tailscale who owns a tailnet address.
type Whois func(ctx context.Context, a netip.Addr) (Caller, error)

// WhoisArgv is the `tailscale` argv for a, which is always a parsed address, after "--".
func WhoisArgv(a netip.Addr) []string { return []string{"whois", "--json", "--", a.String()} }

// TailscaleWhois runs `tailscale whois --json` on this machine.
func TailscaleWhois(ctx context.Context, a netip.Addr) (Caller, error) {
	bin, err := tailnet.Binary()
	if err != nil {
		return Caller{}, err
	}
	out, err := exec.CommandContext(ctx, bin, WhoisArgv(a)...).Output()
	if err != nil {
		return Caller{}, fmt.Errorf("tailscale whois %s: %w", a, withStderr(err))
	}
	return parseWhois(out)
}

func parseWhois(data []byte) (Caller, error) {
	var w struct {
		Node struct {
			ComputedName string
			Tags         []string
		}
		UserProfile struct{ LoginName string }
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return Caller{}, fmt.Errorf("tailscale whois: %w", err)
	}
	c := Caller{Login: strings.ToLower(w.UserProfile.LoginName), Device: w.Node.ComputedName, Tagged: len(w.Node.Tags) > 0}
	if c.Login == "" {
		return Caller{}, errors.New("tailscale whois: no login")
	}
	if c.Login == "tagged-devices" {
		c.Tagged = true
	}
	return c, nil
}

// withStderr adds a failed command's stderr to its error: "exit status 1" alone hides the reason.
func withStderr(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

// Authorizer admits requests whose connection comes from a tailnet device signed in as an allowed login.
type Authorizer struct {
	allow  map[string]bool
	self   map[netip.Addr]bool // the hub machine's own addresses: see RefuseFrom
	whois  Whois
	now    func() time.Time
	OnDeny func(r *http.Request, c Caller, reason string) // audit hook; may be nil

	sem      chan struct{} // limits concurrent whois lookups
	mu       sync.Mutex
	cache    map[netip.Addr]cached
	inflight map[netip.Addr]*call // one lookup per address at a time; others wait for its answer
}

type cached struct {
	c   Caller
	err error
	at  time.Time
}

type call struct {
	done chan struct{}
	c    Caller
	err  error
}

// NewAuthorizer admits only the given logins. With none, it admits nobody.
func NewAuthorizer(allow []string, whois Whois, now func() time.Time) *Authorizer {
	a := &Authorizer{allow: map[string]bool{}, self: map[netip.Addr]bool{}, whois: whois, now: now,
		sem: make(chan struct{}, whoisMax), cache: map[netip.Addr]cached{}, inflight: map[netip.Addr]*call{}}
	for _, l := range allow {
		a.allow[strings.ToLower(l)] = true
	}
	return a
}

// RefuseFrom refuses connections from these addresses: the hub machine's own. A connection from the machine to
// itself carries its own Tailscale address, and whois answers "this machine, signed in as the owner", so any local
// program, user account or URL-fetching service would otherwise pass as the owner.
func (a *Authorizer) RefuseFrom(ips []string) {
	for _, s := range ips {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			a.self[ip.Unmap()] = true
		}
	}
}

// Authorize identifies r's caller from its connection address alone: headers are never consulted.
func (a *Authorizer) Authorize(r *http.Request) (Caller, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return Caller{}, fmt.Errorf("bad remote address %q", r.RemoteAddr)
	}
	addr := ap.Addr().Unmap()
	if !InTailnet(addr) {
		return Caller{Addr: addr.String()}, errors.New("not a tailnet address")
	}
	if a.self[addr] {
		return Caller{Addr: addr.String()}, errors.New("request from the hub machine itself")
	}
	c, err := a.lookup(r.Context(), addr)
	if err != nil {
		return Caller{Addr: addr.String()}, err
	}
	c.Addr = addr.String()
	switch {
	case c.Tagged:
		return c, errors.New("tagged device")
	case !a.allow[c.Login]:
		return c, errors.New("login not allowed")
	}
	return c, nil
}

func (a *Authorizer) lookup(ctx context.Context, addr netip.Addr) (Caller, error) {
	a.mu.Lock()
	if e, ok := a.cache[addr]; ok {
		ttl := whoisTTL
		if e.err != nil {
			ttl = whoisFailTTL
		}
		if a.now().Sub(e.at) < ttl {
			a.mu.Unlock()
			return e.c, e.err
		}
	}
	if cl, ok := a.inflight[addr]; ok {
		a.mu.Unlock()
		select {
		case <-cl.done:
			return cl.c, cl.err
		case <-ctx.Done():
			return Caller{}, ctx.Err()
		}
	}
	cl := &call{done: make(chan struct{})}
	a.inflight[addr] = cl
	a.mu.Unlock()

	// the lookup is shared, so it must not end when the request that started it hangs up
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), whoisTimeout)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
		cl.c, cl.err = a.whois(wctx, addr)
		<-a.sem
	case <-wctx.Done():
		cl.err = wctx.Err()
	}
	a.mu.Lock()
	delete(a.inflight, addr)
	a.cache[addr] = cached{c: cl.c, err: cl.err, at: a.now()}
	a.mu.Unlock()
	close(cl.done)
	return cl.c, cl.err
}

type callerKey struct{}

// CallerFrom returns the caller Wrap admitted.
func CallerFrom(ctx context.Context) Caller {
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}

// Wrap answers 403 to anyone Authorize refuses, and passes the admitted Caller to next in the context.
func (a *Authorizer) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := a.Authorize(r)
		if err != nil {
			if a.OnDeny != nil {
				a.OnDeny(r, c, err.Error())
			}
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ListenAddrs turns this machine's Tailscale IPs into listen addresses. Anything outside the Tailscale ranges is an
// error: on a LAN or wildcard address whois cannot vouch for the caller.
func ListenAddrs(ips []string, port int) ([]string, error) {
	if len(ips) == 0 {
		return nil, errors.New("no Tailscale addresses: is Tailscale up on this machine?")
	}
	var out []string
	for _, s := range ips {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !InTailnet(a) {
			return nil, fmt.Errorf("%q is not a Tailscale address: the hub listens only on the tailnet", s)
		}
		out = append(out, net.JoinHostPort(a.String(), fmt.Sprint(port)))
	}
	return out, nil
}

// TailscaleIPs runs `tailscale ip` on this machine.
func TailscaleIPs(ctx context.Context) ([]string, error) {
	bin, err := tailnet.Binary()
	if err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, bin, "ip").Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale ip: %w", withStderr(err))
	}
	return strings.Fields(string(out)), nil
}
