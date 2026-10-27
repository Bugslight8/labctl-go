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

// Two peers can share a first label: this tailnet's mini and a mini shared in from another tailnet. The short name
// must always mean this tailnet's node, whatever order the JSON map yields; the full name picks either.
func TestLookupSameLabel(t *testing.T) {
	const doc = `{"BackendState": "Running", "MagicDNSSuffix": "tail0000.ts.net", "Self": {"DNSName": "mbp.tail0000.ts.net."},
 "Peer": {
  "a": {"DNSName": "mini.other.ts.net.", "HostName": "shared", "Online": false},
  "b": {"DNSName": "mini.tail0000.ts.net.", "HostName": "Mac-mini", "Online": true},
  "c": {"DNSName": "mini.zzz.ts.net.", "HostName": "shared2", "Online": false}}}`
	for i := 0; i < 200; i++ {
		s, err := Parse(strings.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := s.Lookup("mini"); !ok || p.DNSName != "mini.tail0000.ts.net" {
			t.Fatalf("run %d: Lookup(mini) = %+v, want this tailnet's node", i, p)
		}
		if p, _ := s.Lookup("mini.other.ts.net"); p.HostName != "shared" {
			t.Fatalf("run %d: full name picked %+v", i, p)
		}
	}
	// no node in this tailnet: deterministic (sorted by full name), never map order
	s := &Status{Suffix: "tail0000.ts.net", Peers: []Peer{
		{Name: "mini", DNSName: "mini.zzz.ts.net"}, {Name: "mini", DNSName: "mini.other.ts.net"}}}
	sortPeers(s.Peers)
	if p, _ := s.Lookup("mini"); p.DNSName != "mini.other.ts.net" {
		t.Errorf("tie without a local node = %q", p.DNSName)
	}
}
