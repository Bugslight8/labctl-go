package tailnet

import (
	"os"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T) *Status {
	t.Helper()
	f, err := os.Open("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParse(t *testing.T) {
	s := load(t)
	if s.Self.Name != "macbook-pro" {
		t.Errorf("self = %q", s.Self.Name)
	}
	if len(s.Peers) != 3 {
		t.Fatalf("peers = %d", len(s.Peers))
	}
	// sorted by name, name = first label of the MagicDNS name (not the OS host name)
	got := []string{s.Peers[0].Name, s.Peers[1].Name, s.Peers[2].Name}
	if strings.Join(got, ",") != "fabric-twin,mini,pi" {
		t.Errorf("names = %v", got)
	}
	ft := s.Peers[0]
	if ft.Online || ft.OS != "windows" || ft.IP != "100.64.0.3" {
		t.Errorf("fabric-twin = %+v", ft)
	}
	if want := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC); !ft.LastSeen.Equal(want) {
		t.Errorf("last seen = %v", ft.LastSeen)
	}
	if s.Peers[1].OS != "macos" || s.Peers[1].IP != "100.64.0.2" {
		t.Errorf("mini = %+v (want OS lowercased, IPv4 first)", s.Peers[1])
	}
}

func TestLookup(t *testing.T) {
	s := load(t)
	for _, q := range []string{"fabric-twin", "DESKTOP-7", "fabric-twin.tail0000.ts.net"} {
		if p, ok := s.Lookup(q); !ok || p.Name != "fabric-twin" {
			t.Errorf("Lookup(%q) = %+v, %v", q, p, ok)
		}
	}
	if _, ok := s.Lookup("ghost"); ok {
		t.Error("Lookup(ghost) found something")
	}
}

func TestParseRejectsStoppedBackend(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"BackendState": "Stopped", "Self": {}}`))
	if err == nil || !strings.Contains(err.Error(), "Stopped") {
		t.Errorf("err = %v, want one naming the Stopped state", err)
	}
}

func TestLookupPrefersMagicDNSName(t *testing.T) {
	s := &Status{Peers: []Peer{{Name: "alpha", HostName: "mini"}, {Name: "mini", HostName: "Mac-mini", Online: true}}}
	if p, _ := s.Lookup("mini"); p.Name != "mini" {
		t.Errorf("Lookup(mini) = %q: a peer naming itself mini must not shadow mini's MagicDNS name", p.Name)
	}
}
