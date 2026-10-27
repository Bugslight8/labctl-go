package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWhois maps Tailscale addresses to callers and counts lookups.
type fakeWhois struct {
	callers map[string]Caller
	calls   []string
	err     error
}

func (f *fakeWhois) whois(_ context.Context, a netip.Addr) (Caller, error) {
	f.calls = append(f.calls, a.String())
	if f.err != nil {
		return Caller{}, f.err
	}
	c, ok := f.callers[a.String()]
	if !ok {
		return Caller{}, errors.New("no such peer")
	}
	return c, nil
}

const (
	ownerAddr    = "100.64.0.1"
	strangerAddr = "100.64.0.66"
	taggedAddr   = "100.64.0.77"
)

func newAuth(t *testing.T) (*Authorizer, *fakeWhois, *time.Time) {
	t.Helper()
	fw := &fakeWhois{callers: map[string]Caller{
		ownerAddr:    {Login: "owner@example.com", Device: "macbook-pro"},
		strangerAddr: {Login: "someone@else.com", Device: "their-laptop"},
		taggedAddr:   {Login: "tagged-devices", Device: "ci-runner", Tagged: true},
	}}
	clock := t0
	a := NewAuthorizer([]string{"owner@example.com"}, fw.whois, func() time.Time { return clock })
	return a, fw, &clock
}

func request(remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/hosts", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func serve(a *Authorizer, r *http.Request) (int, string) {
	var who string
	h := a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who = CallerFrom(r.Context()).Login
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, who
}

// T1: only the allowed login gets in; strangers, tagged devices, non-tailnet addresses and whois failures do not.
func TestAccess(t *testing.T) {
	a, fw, clock := newAuth(t)
	if code, who := serve(a, request(ownerAddr+":5000", nil)); code != 200 || who != "owner@example.com" {
		t.Errorf("owner: %d %q", code, who)
	}
	for what, remote := range map[string]string{
		"stranger":    strangerAddr + ":5000",
		"tagged":      taggedAddr + ":5000",
		"unknown":     "100.64.0.99:5000",
		"lan address": "192.168.1.20:5000",
		"loopback":    "127.0.0.1:5000",
	} {
		if code, _ := serve(a, request(remote, nil)); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", what, code)
		}
	}
	for _, c := range fw.calls {
		if c == "192.168.1.20" || c == "127.0.0.1" {
			t.Errorf("whois asked about non-tailnet address %s", c)
		}
	}

	// one whois per address per minute
	fw.calls = nil
	serve(a, request(ownerAddr+":5001", nil))
	serve(a, request(ownerAddr+":5002", nil))
	if len(fw.calls) != 0 {
		t.Errorf("cached owner looked up again: %v", fw.calls)
	}
	*clock = clock.Add(11 * time.Second) // security L1: a short TTL, as addresses can move to another device
	serve(a, request(ownerAddr+":5003", nil))
	if len(fw.calls) != 1 {
		t.Errorf("after 11 s want one fresh whois, got %v", fw.calls)
	}

	// fail closed when whois fails; the failure is cached for 5 s
	fw.err = errors.New("tailscaled down")
	*clock = clock.Add(11 * time.Second)
	fw.calls = nil
	for i := 0; i < 3; i++ {
		if code, _ := serve(a, request(ownerAddr+":5004", nil)); code != http.StatusForbidden {
			t.Errorf("whois failure: %d, want 403", code)
		}
	}
	if len(fw.calls) != 1 {
		t.Errorf("failed lookups: %d whois calls, want 1 (cached)", len(fw.calls))
	}
	*clock = clock.Add(6 * time.Second)
	serve(a, request(ownerAddr+":5005", nil))
	if len(fw.calls) != 2 {
		t.Errorf("after 6 s the failure must be retried: %d calls", len(fw.calls))
	}

	// an empty allow list refuses everyone
	empty := NewAuthorizer(nil, fw.whois, time.Now)
	fw.err = nil
	if code, _ := serve(empty, request(ownerAddr+":5000", nil)); code != http.StatusForbidden {
		t.Errorf("empty allow: %d", code)
	}
}

// T3: identity comes from the connection, never from a header.
func TestIdentityIgnoresHeaders(t *testing.T) {
	a, fw, _ := newAuth(t)
	hdr := map[string]string{
		"X-Forwarded-For":            ownerAddr,
		"X-Real-IP":                  ownerAddr,
		"Forwarded":                  "for=" + ownerAddr,
		"Tailscale-User-Login":       "owner@example.com",
		"Tailscale-User-Name":        "Owner",
		"X-Webauth-User":             "owner@example.com",
		"X-Forwarded-Tailscale-User": "owner@example.com",
	}
	if code, _ := serve(a, request(strangerAddr+":5000", hdr)); code != http.StatusForbidden {
		t.Errorf("stranger with owner headers: %d, want 403", code)
	}
	if !reflect.DeepEqual(fw.calls, []string{strangerAddr}) {
		t.Errorf("whois calls %v, want only the connection's address", fw.calls)
	}
}

// T8: only a parsed IP reaches the tailscale argv, after "--".
func TestWhoisArgv(t *testing.T) {
	if got := WhoisArgv(netip.MustParseAddr("100.64.0.1")); !reflect.DeepEqual(got, []string{"whois", "--json", "--", "100.64.0.1"}) {
		t.Errorf("v4 argv %q", got)
	}
	if got := WhoisArgv(netip.MustParseAddr("fd7a:115c:a1e0::5")); got[len(got)-1] != "fd7a:115c:a1e0::5" {
		t.Errorf("v6 argv %q", got)
	}
	a, fw, _ := newAuth(t)
	for _, remote := range []string{"-oFoo:1", "[--json]:1", "100.64.0.1", "", "100.64.0.1:x"} {
		if code, _ := serve(a, request(remote, nil)); code != http.StatusForbidden {
			t.Errorf("RemoteAddr %q: %d", remote, code)
		}
	}
	if len(fw.calls) != 0 {
		t.Errorf("unparsable addresses reached whois: %v", fw.calls)
	}
}

func TestParseWhois(t *testing.T) {
	c, err := parseWhois([]byte(`{"Node": {"ComputedName": "macbook-pro", "Tags": null},
		"UserProfile": {"LoginName": "Owner@Example.com"}}`))
	if err != nil || c.Login != "owner@example.com" || c.Device != "macbook-pro" || c.Tagged {
		t.Errorf("user node: %+v %v", c, err)
	}
	c, err = parseWhois([]byte(`{"Node": {"ComputedName": "ci", "Tags": ["tag:server"]},
		"UserProfile": {"LoginName": "owner@example.com"}}`))
	if err != nil || !c.Tagged {
		t.Errorf("tagged node must be Tagged even with a user's login: %+v %v", c, err)
	}
	if _, err := parseWhois([]byte(`{"Node": {}, "UserProfile": {"LoginName": ""}}`)); err == nil {
		t.Error("empty login accepted")
	}
}

// T2: listen only on Tailscale addresses, never a wildcard or a LAN address.
func TestListenAddrs(t *testing.T) {
	got, err := ListenAddrs([]string{"100.64.0.2", "fd7a:115c:a1e0::2"}, 7300)
	if err != nil || !reflect.DeepEqual(got, []string{"100.64.0.2:7300", "[fd7a:115c:a1e0::2]:7300"}) {
		t.Errorf("tailnet addrs: %v %v", got, err)
	}
	for _, bad := range [][]string{{"0.0.0.0"}, {"::"}, {"192.168.1.2"}, {"100.64.0.2", "10.0.0.5"}, {}, {"localhost"}, {"100.128.0.1"}} {
		if _, err := ListenAddrs(bad, 7300); err == nil {
			t.Errorf("%v accepted", bad)
		} else if len(bad) > 0 && !strings.Contains(err.Error(), "Tailscale") {
			t.Errorf("%v: unhelpful error %v", bad, err)
		}
	}
}

// security M1: a program on the hub machine reaches it from the machine's own Tailscale address, which whois
// reports as the owner; it must be refused before whois.
func TestAccessRefusesSelf(t *testing.T) {
	a, fw, _ := newAuth(t)
	fw.callers["100.64.0.10"] = Caller{Login: "owner@example.com", Device: "mini"}
	a.RefuseFrom([]string{"100.64.0.10", "fd7a:115c:a1e0::10"})
	for _, remote := range []string{"100.64.0.10:5000", "[fd7a:115c:a1e0::10]:5000", "[::ffff:100.64.0.10]:5000"} {
		if code, _ := serve(a, request(remote, nil)); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", remote, code)
		}
	}
	if len(fw.calls) != 0 {
		t.Errorf("self requests reached whois: %v", fw.calls)
	}
	if code, _ := serve(a, request(ownerAddr+":5000", nil)); code != 200 {
		t.Errorf("owner still admitted: %d", code)
	}
}

// security M4: a burst from one address makes one whois; bursts from many addresses run at most whoisMax at once
func TestWhoisLimits(t *testing.T) {
	var mu sync.Mutex
	calls, running, peak := 0, 0, 0
	slow := func(_ context.Context, a netip.Addr) (Caller, error) {
		mu.Lock()
		calls++
		running++
		if running > peak {
			peak = running
		}
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		running--
		mu.Unlock()
		return Caller{Login: "someone@else.com"}, nil
	}
	a := NewAuthorizer([]string{"owner@example.com"}, slow, time.Now)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); serve(a, request(strangerAddr+":5000", nil)) }()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("200 requests from one address made %d whois calls, want 1", calls)
	}
	calls, peak = 0, 0
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); serve(a, request(fmt.Sprintf("100.64.1.%d:5000", i), nil)) }(i)
	}
	wg.Wait()
	if calls != 40 || peak > whoisMax {
		t.Errorf("40 addresses: %d calls, peak %d concurrent (max %d)", calls, peak, whoisMax)
	}
}
