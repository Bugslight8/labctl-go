// Package hubclient is the client side of the hub API: the MacBook (or any device) asks the hub for the host list,
// its live events and wakes, and keeps a cached copy of the list for when the hub is down.
package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/inventory"
)

const (
	requestTimeout = 3 * time.Second
	pollTimeout    = 40 * time.Second // the hub holds a long poll for up to 25 s
	maxBody        = 1 << 20
)

// Client talks to one hub, addressed by its MagicDNS name.
type Client struct {
	base string // http://<host>:<port>
	http *http.Client
}

// New makes a client for host:port. dial opens the connection: SystemDialer().DialContext on a real device.
func New(host string, port int, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Client {
	return &Client{
		base: "http://" + net.JoinHostPort(host, strconv.Itoa(port)),
		http: &http.Client{Transport: &http.Transport{DialContext: dial, Proxy: nil}},
	}
}

func (c *Client) do(ctx context.Context, method, path string, timeout time.Duration, v any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return err
	}
	if method != http.MethodGet {
		req.Header.Set("X-Labctl", "1")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode/100 != 2 {
		var msg struct{ Result, Error string }
		_ = json.NewDecoder(body).Decode(&msg)
		if resp.StatusCode == http.StatusForbidden {
			return errors.New("the hub refused this device: is it signed in to Tailscale as an allowed login?")
		}
		return fmt.Errorf("hub: %s (%d)", msg.Result+msg.Error, resp.StatusCode)
	}
	if v == nil {
		return nil
	}
	return json.NewDecoder(body).Decode(v)
}

// Hosts fetches the hub's host list, refusing it whole when any host fails the inventory rules (T1).
func (c *Client) Hosts(ctx context.Context) (*hub.HostsResponse, error) {
	var r hub.HostsResponse
	if err := c.do(ctx, http.MethodGet, "/v1/hosts", requestTimeout, &r); err != nil {
		return nil, err
	}
	if _, err := Inventory(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Events long-polls for events after since; boot is the hub start the client's numbers come from ("" at first).
func (c *Client) Events(ctx context.Context, since uint64, boot string) (*hub.EventsResponse, error) {
	q := url.Values{"since": {strconv.FormatUint(since, 10)}}
	if boot != "" {
		q.Set("boot", boot)
	}
	var r hub.EventsResponse
	if err := c.do(ctx, http.MethodGet, "/v1/events?"+q.Encode(), pollTimeout, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Wake asks the hub to send name's magic packet.
func (c *Client) Wake(ctx context.Context, name string) error {
	if err := inventory.CheckHost(inventory.Host{Name: name, Tailnet: name}); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/v1/wake/"+url.PathEscape(name), requestTimeout, nil)
}

// Inventory turns a hub answer into hosts, applying the same rules as the hosts file to every field that reaches
// ssh. The hub never sends MACs: a wakeable host is woken through the hub.
func Inventory(r *hub.HostsResponse) ([]inventory.Host, error) {
	var out []inventory.Host
	for _, hi := range r.Hosts {
		h := inventory.Host{Name: hi.Name, Tailnet: hi.Tailnet, User: hi.User, OS: hi.OS, Tmux: hi.Tmux, HubWakeable: hi.Wakeable}
		if err := inventory.CheckHost(h); err != nil {
			return nil, fmt.Errorf("the hub's host list has an unsafe host: %w", err)
		}
		out = append(out, h)
	}
	return out, nil
}

// SaveCache writes the last good hub answer to path (mode 0600), replacing it in one rename.
func SaveCache(path string, r *hub.HostsResponse) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hosts-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadCache reads the cached answer and when it was written, applying the same host rules as a live answer.
func LoadCache(path string) (*hub.HostsResponse, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var r hub.HostsResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := Inventory(&r); err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	return &r, fi.ModTime(), nil
}

// Dialer connects to the hub only at Tailscale addresses (T2): whatever DNS says, a LAN or public address that
// answers for the hub's name is never dialed, so no other machine can stand in for it.
type Dialer struct {
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SystemDialer resolves with the system resolver (Tailscale's MagicDNS on a tailnet device).
func SystemDialer() Dialer {
	return Dialer{
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		Dial: (&net.Dialer{Timeout: requestTimeout}).DialContext,
	}
}

// DialContext is for http.Transport.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = d.Lookup(ctx, host); err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if hub.InTailnet(ip) {
			return d.Dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		}
	}
	return nil, fmt.Errorf("%s does not resolve to a Tailscale address, so it is not your hub", host)
}
