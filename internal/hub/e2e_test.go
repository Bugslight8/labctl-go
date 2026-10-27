package hub

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// remoteListener makes every accepted connection look like it comes from one tailnet address, so a loopback test
// can be "the owner's MacBook" on one listener and "a stranger" on another.
type remoteListener struct {
	net.Listener
	as net.Addr
}

type remoteConn struct {
	net.Conn
	as net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.as }

func (l remoteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return remoteConn{c, l.as}, nil
}

// TestHubEndToEnd runs the real Serve (HTTP servers, guard, whois authorizer, monitor, audit) with fake tailscale,
// whois, port probes and WoL, over real TCP on loopback.
func TestHubEndToEnd(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.toml")
	if err := os.WriteFile(hosts, []byte(hostsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	lab := newFakeLab()
	fw := &fakeWhois{callers: map[string]Caller{
		ownerAddr:    {Login: "owner@example.com", Device: "macbook-pro"},
		strangerAddr: {Login: "someone@else.com", Device: "their-laptop"},
	}}
	var mu sync.Mutex
	var sent []string
	requested := map[string]string{} // tailnet listen addr -> loopback addr
	ready := make(chan struct{})
	state := filepath.Join(dir, "state")

	opts := Options{
		HostsPath: hosts,
		StateDir:  state,
		Stderr:    io.Discard,
		Status:    lab.status,
		Whois:     fw.whois,
		IPs:       func(context.Context) ([]string, error) { return []string{"100.64.0.10", "fd7a:115c:a1e0::10"}, nil },
		Dial:      lab.dial,
		SendWOL: func(mac net.HardwareAddr, addr string) error {
			mu.Lock()
			sent = append(sent, mac.String())
			mu.Unlock()
			return nil
		},
		Now: time.Now,
		Listen: func(network, addr string) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			as := &net.TCPAddr{IP: net.ParseIP(ownerAddr), Port: 41000}
			if strings.HasPrefix(addr, "[") {
				as = &net.TCPAddr{IP: net.ParseIP(strangerAddr), Port: 41001}
			}
			mu.Lock()
			requested[addr] = ln.Addr().String()
			mu.Unlock()
			return remoteListener{ln, as}, nil
		},
		PollEvery: 20 * time.Millisecond,
		LongPoll:  30 * time.Second, // longer than the stop deadline below: stopping must not wait for it
		Ready:     func([]string) { close(ready) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, opts) }()
	select {
	case <-ready:
	case err := <-served:
		t.Fatalf("Serve: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not start")
	}
	mu.Lock()
	ownerURL, strangerURL := "http://"+requested["100.64.0.10:7300"], "http://"+requested["[fd7a:115c:a1e0::10]:7300"]
	mu.Unlock()
	if len(requested) != 2 || ownerURL == "http://" || strangerURL == "http://" {
		t.Fatalf("listened on %v, want exactly the two Tailscale addresses on port 7300", requested)
	}

	get := func(url string, v any) int {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if v != nil {
			if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}

	// the owner sees the baseline events and the hosts
	var ev EventsResponse
	if code := get(ownerURL+"/v1/events?since=0", &ev); code != 200 || len(ev.Events) != 3 {
		t.Fatalf("baseline events: %d %+v", code, ev)
	}
	var hostList HostsResponse
	if code := get(ownerURL+"/v1/hosts", &hostList); code != 200 || len(hostList.Hosts) != 3 || hostList.Hosts[0].State != "up" {
		t.Fatalf("hosts: %d %+v", code, hostList)
	}

	// a live event reaches a waiting long poll
	live := make(chan EventsResponse, 1)
	go func() {
		var r EventsResponse
		get(ownerURL+"/v1/events?since="+itoa(ev.Last), &r)
		live <- r
	}()
	time.Sleep(50 * time.Millisecond)
	lab.setOnline("fabric-twin", false)
	select {
	case r := <-live:
		if len(r.Events) != 1 || r.Events[0].Host != "fabric-twin" || r.Events[0].To != "asleep" {
			t.Errorf("live events %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no live event")
	}

	// the owner wakes a host; the hub sends the inventory MAC itself
	req, _ := http.NewRequest("POST", ownerURL+"/v1/wake/fabric-twin", nil)
	req.Header.Set("X-Labctl", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	gotSent := append([]string(nil), sent...)
	mu.Unlock()
	if resp.StatusCode != http.StatusAccepted || len(gotSent) != 1 || gotSent[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("wake: %d, sent %v", resp.StatusCode, gotSent)
	}

	// a stranger on the tailnet gets nothing
	if code := get(strangerURL+"/v1/hosts", nil); code != http.StatusForbidden {
		t.Errorf("stranger: %d", code)
	}

	// stopping must be prompt even with a long poll waiting and a connection that never sent a request
	// (Go's server otherwise waits up to the poll's end, or 5 s, for each)
	idle, err := net.Dial("tcp", strings.TrimPrefix(ownerURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	go func() {
		if resp, err := http.Get(ownerURL + "/v1/events?since=999999"); err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	stopAt := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v after cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hub did not stop within 3 s")
	}
	if d := time.Since(stopAt); d > 2500*time.Millisecond {
		t.Errorf("stop took %v", d)
	}
	audit, _ := os.ReadFile(filepath.Join(state, "audit.jsonl"))
	if !strings.Contains(string(audit), `"action":"wake","host":"fabric-twin","result":"sent"`) || !strings.Contains(string(audit), "someone@else.com") {
		t.Errorf("audit log:\n%s", audit)
	}
}

func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func TestServeRefusesWithoutHubTable(t *testing.T) {
	hosts := filepath.Join(t.TempDir(), "hosts.toml")
	os.WriteFile(hosts, []byte("[[host]]\nname = \"a\"\n"), 0o600)
	err := Serve(context.Background(), Options{HostsPath: hosts})
	if err == nil || !strings.Contains(err.Error(), "[hub]") {
		t.Errorf("err = %v", err)
	}
	hosts2 := filepath.Join(t.TempDir(), "hosts.toml")
	os.WriteFile(hosts2, []byte(hostsFile), 0o600)
	err = Serve(context.Background(), Options{HostsPath: hosts2,
		IPs: func(context.Context) ([]string, error) { return []string{"0.0.0.0"}, nil }})
	if err == nil || !strings.Contains(err.Error(), "Tailscale") {
		t.Errorf("wildcard listen: err = %v", err)
	}
}
