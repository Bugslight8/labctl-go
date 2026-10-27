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
	"strings"
	"time"
	"unicode"

	"github.com/Bugslight8/labctl/internal/hub"
	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/tailnet"
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
		http: &http.Client{
			Transport: &http.Transport{DialContext: dial, Proxy: nil}, // no proxy: the dialer decides where we connect
			// never follow a redirect: it would carry X-Labctl to wherever the answer points
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
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
		return statusError{resp.StatusCode, fmt.Sprintf("hub: %s (%d)", printable(msg.Result+msg.Error, 200), resp.StatusCode)}
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
	if r.Hosts == nil { // the hub always sends a list, empty or not: a missing one is a different or broken server
		return nil, errors.New("hub: the answer has no host list")
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
	if r.Events == nil || r.Boot == "" {
		return nil, errors.New("hub: the events answer has no events list or boot id")
	}
	return &r, nil
}

// ErrRecentlyWoken: the hub sent this host's packet less than 10 s ago (and so sends no other yet).
var ErrRecentlyWoken = errors.New("the hub woke it less than 10 s ago")

// Wake asks the hub to send name's magic packet.
func (c *Client) Wake(ctx context.Context, name string) error {
	if err := inventory.CheckHost(inventory.Host{Name: name, Tailnet: name}); err != nil {
		return err
	}
	err := c.do(ctx, http.MethodPost, "/v1/wake/"+url.PathEscape(name), requestTimeout, nil)
	var se statusError
	if errors.As(err, &se) && se.code == http.StatusTooManyRequests {
		return ErrRecentlyWoken
	}
	return err
}

// statusError is a non-2xx answer.
type statusError struct {
	code int
	msg  string
}

func (e statusError) Error() string { return e.msg }

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
	return os.Rename(tmp.Name(), path) // CreateTemp made it 0600
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

// printable drops control characters (terminal escape sequences) from text the hub sends, and clips it.
func printable(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

// Dialer connects to the hub only at the address this machine's Tailscale gives for it (T2). DNS is never asked:
// on another network, or with Tailscale or MagicDNS off, a DNS answer in Tailscale's ranges (shared carrier space)
// can point anywhere. The hub must be a peer of this tailnet (not a node shared in from another) with that name.
type Dialer struct {
	Status func(ctx context.Context) (*tailnet.Status, error) // fails unless Tailscale is running
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SystemDialer asks the local tailscale CLI.
func SystemDialer() Dialer {
	return Dialer{Status: tailnet.Query, Dial: (&net.Dialer{Timeout: requestTimeout}).DialContext}
}

// DialContext is for http.Transport.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	st, err := d.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("finding the hub needs Tailscale: %w", err)
	}
	if p, ok := hubPeer(st, host); ok {
		return d.Dial(ctx, network, net.JoinHostPort(p.IP, port))
	}
	return nil, fmt.Errorf("%s is not a device in your tailnet, so it is not your hub", host)
}

// hubPeer finds the peer of this tailnet (DNSName = name + this tailnet's suffix) that host names, by short or full
// MagicDNS name or by its Tailscale IP.
func hubPeer(st *tailnet.Status, host string) (tailnet.Peer, bool) {
	ip, perr := netip.ParseAddr(host)
	isIP := perr == nil
	full := strings.TrimSuffix(host, ".")
	for _, p := range st.Peers {
		if st.Suffix == "" || !strings.EqualFold(p.DNSName, p.Name+"."+st.Suffix) || p.IP == "" {
			continue // shared in from another tailnet, or no address
		}
		switch {
		case isIP && ip.Unmap().String() == p.IP:
		case !isIP && (strings.EqualFold(full, p.Name) || strings.EqualFold(full, p.DNSName)):
		default:
			continue
		}
		return p, true
	}
	return tailnet.Peer{}, false
}
