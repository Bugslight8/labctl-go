package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
)

type apiHarness struct {
	srv   *Server
	mon   *Monitor
	lab   *fakeLab
	sent  []string // "mac addr" per magic packet
	clock *time.Time
	dir   string
}

func newAPI(t *testing.T) *apiHarness {
	t.Helper()
	inv, err := inventory.Parse([]byte(hostsFile))
	if err != nil {
		t.Fatal(err)
	}
	h := &apiHarness{lab: newFakeLab(), dir: filepath.Join(t.TempDir(), "state")}
	clock := t0
	h.clock = &clock
	now := func() time.Time { return *h.clock }
	h.mon = NewMonitor(inv, h.lab.status, h.lab.dial, now)
	if err := h.mon.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	auth, _, _ := newAuth(t)
	audit, err := OpenAudit(h.dir, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	h.srv = &Server{
		Inv: inv, Mon: h.mon, Auth: auth, Audit: audit, Now: now, LongPoll: 50 * time.Millisecond,
		AllowedHosts: []string{"mini", "mini.tail0000.ts.net", "100.64.0.10"},
		SendWOL: func(mac net.HardwareAddr, addr string) error {
			h.sent = append(h.sent, mac.String()+" "+addr)
			return nil
		},
	}
	return h
}

func (h *apiHarness) do(method, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote
	r.Host = "mini:7300"
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, r)
	return rec
}

var owner = ownerAddr + ":4000"
var wakeHdr = map[string]string{"X-Labctl": "1"}

func TestHostsAPI(t *testing.T) {
	h := newAPI(t)
	rec := h.do("GET", "/v1/hosts", owner, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var body HostsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Relay != "mini" || len(body.Hosts) != 3 {
		t.Fatalf("body %+v", body)
	}
	ft := body.Hosts[1]
	if ft.Name != "fabric-twin" || ft.State != string(Unreachable) || !ft.Wakeable || ft.OS != "windows" || ft.Tmux != "main" {
		t.Errorf("fabric-twin %+v", ft)
	}
	if body.Hosts[0].Wakeable {
		t.Error("mini has no mac but is wakeable")
	}
	if body.Hosts[0].State != string(Up) || body.Hosts[0].IP != "100.64.0.10" {
		t.Errorf("the hub's own machine: %+v", body.Hosts[0])
	}
	if strings.Contains(rec.Body.String(), "aa:bb:cc") || strings.Contains(rec.Body.String(), "owner@example.com") {
		t.Errorf("hosts answer leaks MACs or the allow list:\n%s", rec.Body)
	}
	if rec := h.do("GET", "/v1/hosts", strangerAddr+":4000", nil); rec.Code != http.StatusForbidden {
		t.Errorf("stranger: %d", rec.Code)
	}
}

func TestEventsAPI(t *testing.T) {
	h := newAPI(t)
	var body EventsResponse
	rec := h.do("GET", "/v1/events?since=0", owner, nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || len(body.Events) != 3 || body.Last != 3 || body.Boot != h.mon.Boot {
		t.Fatalf("baseline: %d %s", rec.Code, rec.Body)
	}
	// a client from before a hub restart (other boot) starts over from 0 at once
	rec = h.do("GET", "/v1/events?since=2&boot=oldboot", owner, nil)
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || len(body.Events) != 3 {
		t.Errorf("stale boot: %s", rec.Body)
	}
	// nothing new: the long poll ends empty after LongPoll
	start := time.Now()
	rec = h.do("GET", "/v1/events?since=3", owner, nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || len(body.Events) != 0 || body.Last != 3 {
		t.Errorf("empty poll: %d %s", rec.Code, rec.Body)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("empty poll returned after %v, want it to wait", time.Since(start))
	}
	// a change during the wait is delivered
	go func() { time.Sleep(10 * time.Millisecond); h.mon.record("nas", Asleep) }()
	h.srv.LongPoll = 2 * time.Second
	rec = h.do("GET", "/v1/events?since=3", owner, nil)
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || len(body.Events) != 1 || body.Events[0].To != "asleep" {
		t.Errorf("live event: %s", rec.Body)
	}
	for _, bad := range []string{"/v1/events?since=x", "/v1/events?since=-1"} {
		if rec := h.do("GET", bad, owner, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
}

// T4: a web page in the owner's browser cannot drive the hub.
func TestCSRF(t *testing.T) {
	h := newAPI(t)
	cases := []struct {
		method, path string
		hdr          map[string]string
	}{
		{"POST", "/v1/wake/fabric-twin", nil},
		{"POST", "/v1/wake/fabric-twin", map[string]string{"X-Labctl": "1", "Origin": "https://evil.example"}},
		{"POST", "/v1/wake/fabric-twin", map[string]string{"X-Labctl": "yes"}},
		{"GET", "/v1/hosts", map[string]string{"Origin": "https://evil.example"}},
		{"OPTIONS", "/v1/wake/fabric-twin", map[string]string{"Origin": "https://evil.example"}},
	}
	for _, c := range cases {
		rec := h.do(c.method, c.path, owner, c.hdr)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s %v: %d", c.method, c.path, c.hdr, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("CORS header sent")
		}
	}
	if len(h.sent) != 0 {
		t.Errorf("a refused request sent packets: %v", h.sent)
	}
	if rec := h.do("GET", "/v1/wake/fabric-twin", owner, wakeHdr); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET wake: %d", rec.Code)
	}
}

// T5: only inventory names reach the wake path, with the inventory's MAC.
func TestWakeUnknownHost(t *testing.T) {
	h := newAPI(t)
	for _, path := range []string{"/v1/wake/ghost", "/v1/wake/-oProxyCommand=x", "/v1/wake/fabric-twin%3Breboot", "/v1/wake/..%2Fetc"} {
		if rec := h.do("POST", path, owner, wakeHdr); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := h.do("POST", "/v1/wake/mini", owner, wakeHdr); rec.Code != http.StatusConflict {
		t.Errorf("host without mac: %d", rec.Code)
	}
	if len(h.sent) != 0 {
		t.Errorf("sent %v", h.sent)
	}
}

// T6: at most one wake per host per 10 s.
func TestWakeRateLimit(t *testing.T) {
	h := newAPI(t)
	if rec := h.do("POST", "/v1/wake/FABRIC-TWIN", owner, wakeHdr); rec.Code != http.StatusAccepted {
		t.Fatalf("first wake: %d %s", rec.Code, rec.Body)
	}
	if len(h.sent) != 1 || h.sent[0] != "aa:bb:cc:dd:ee:01 255.255.255.255:9" {
		t.Fatalf("sent %v", h.sent)
	}
	*h.clock = h.clock.Add(9 * time.Second)
	if rec := h.do("POST", "/v1/wake/fabric-twin", owner, wakeHdr); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second wake within 10 s: %d", rec.Code)
	}
	*h.clock = h.clock.Add(2 * time.Second)
	if rec := h.do("POST", "/v1/wake/fabric-twin", owner, wakeHdr); rec.Code != http.StatusAccepted {
		t.Errorf("wake after 11 s: %d", rec.Code)
	}
	if len(h.sent) != 2 {
		t.Errorf("sent %v", h.sent)
	}

	// a failed send does not use up the slot: the retry goes out at once
	*h.clock = h.clock.Add(11 * time.Second)
	h.srv.SendWOL = func(net.HardwareAddr, string) error { return errors.New("network is down") }
	if rec := h.do("POST", "/v1/wake/fabric-twin", owner, wakeHdr); rec.Code != http.StatusBadGateway {
		t.Errorf("failed send: %d", rec.Code)
	}
	h.srv.SendWOL = func(net.HardwareAddr, string) error { return nil }
	if rec := h.do("POST", "/v1/wake/fabric-twin", owner, wakeHdr); rec.Code != http.StatusAccepted {
		t.Errorf("retry after a failed send: %d", rec.Code)
	}
}

// review 8: the hub sends the packet itself, so a host with a MAC is wakeable even without a relay setting
func TestWakeableWithoutRelay(t *testing.T) {
	h := newAPI(t)
	inv, err := inventory.Parse([]byte(strings.Replace(hostsFile, `relay = "mini"`, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	h.srv.Inv = inv
	var body HostsResponse
	json.Unmarshal(h.do("GET", "/v1/hosts", owner, nil).Body.Bytes(), &body)
	if !body.Hosts[1].Wakeable {
		t.Errorf("fabric-twin has a mac: %+v", body.Hosts[1])
	}
}

// security M3: a DNS-rebinding page is same-origin (no Origin header) but carries its own Host and Sec-Fetch-*
func TestDNSRebinding(t *testing.T) {
	h := newAPI(t)
	for _, hdr := range []map[string]string{
		{"Host": "evil.example:7300"},
		{"Host": "evil.example"},
		{"Host": "100.64.0.10.evil.example:7300"},
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Mode": "cors"},
	} {
		if rec := h.do("GET", "/v1/hosts", owner, hdr); rec.Code != http.StatusForbidden {
			t.Errorf("%v: %d", hdr, rec.Code)
		}
	}
	for _, host := range []string{"mini:7300", "MINI.tail0000.ts.net:7300", "mini.tail0000.ts.net.:7300", "100.64.0.10:7300", "mini"} {
		if rec := h.do("GET", "/v1/hosts", owner, map[string]string{"Host": host}); rec.Code != 200 {
			t.Errorf("Host %q: %d", host, rec.Code)
		}
	}
}

// security M2: refusals cannot fill the disk: logged once per address per minute, paths cut, file rotated
func TestAuditLimits(t *testing.T) {
	h := newAPI(t)
	long := "/v1/" + strings.Repeat("A", 5000)
	for i := 0; i < 50; i++ {
		h.do("GET", long, strangerAddr+":4000", nil)
	}
	h.srv.Audit.Close()
	data, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || len(lines[0]) > 600 {
		t.Fatalf("%d records, first %d bytes", len(lines), len(lines[0]))
	}
	*h.clock = h.clock.Add(61 * time.Second)
	a, err := OpenAudit(h.dir, func() time.Time { return *h.clock })
	if err != nil {
		t.Fatal(err)
	}
	h.srv.Audit = a
	h.do("GET", long, strangerAddr+":4000", nil)
	if a.size == 0 {
		t.Error("a refusal a minute later was not logged")
	}

	// rotation: past the cap, audit.jsonl moves to audit.jsonl.1 and a new one starts
	a.max = 400
	for i := 0; i < 5; i++ {
		a.Log(AuditRecord{Action: "wake", Host: "fabric-twin", Result: "sent"})
	}
	a.Close()
	if fi, err := os.Stat(filepath.Join(h.dir, "audit.jsonl.1")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("rotated file: %v %v", fi, err)
	}
	if fi, _ := os.Stat(filepath.Join(h.dir, "audit.jsonl")); fi.Size() > 400 || fi.Mode().Perm() != 0o600 {
		t.Errorf("current file %d bytes, mode %v", fi.Size(), fi.Mode().Perm())
	}
}

// T7: the audit log is private and records allowed and refused actions.
func TestAuditFile(t *testing.T) {
	h := newAPI(t)
	h.do("POST", "/v1/wake/fabric-twin", owner, wakeHdr)
	h.do("GET", "/v1/hosts", strangerAddr+":4000", nil)
	h.srv.Audit.Close()

	path := filepath.Join(h.dir, "audit.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []AuditRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("not JSON: %q", sc.Text())
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("records %+v", recs)
	}
	if recs[0].Login != "owner@example.com" || recs[0].Action != "wake" || recs[0].Host != "fabric-twin" || recs[0].Result != "sent" || recs[0].Device != "macbook-pro" {
		t.Errorf("wake record %+v", recs[0])
	}
	if recs[1].Login != "someone@else.com" || !strings.HasPrefix(recs[1].Result, "denied") || recs[1].Addr != strangerAddr {
		t.Errorf("denied record %+v", recs[1])
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("audit file mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(h.dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v", fi.Mode().Perm())
	}

	// an existing audit file that others can read is tightened, not trusted
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(h.dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("reopened audit file mode %v", fi.Mode().Perm())
	}
}

// review round 2: the refusal dedupe must not hide wake attempts. Every refused wake is logged, at most once per
// address per host per minute (unknown names share one slot, so made-up names cannot flood the log).
func TestAuditRefusedWakes(t *testing.T) {
	h := newAPI(t)
	stranger := strangerAddr + ":4000"
	h.do("GET", "/v1/hosts", stranger, nil)
	h.do("POST", "/v1/wake/fabric-twin", stranger, wakeHdr) // logged, despite the GET refusal just before
	h.do("POST", "/v1/wake/fabric-twin", stranger, wakeHdr) // same host, same minute: not again
	h.do("POST", "/v1/wake/nas", stranger, wakeHdr)         // another host: logged
	h.do("POST", "/v1/wake/ghost1", stranger, wakeHdr)      // unknown names: one slot together
	h.do("POST", "/v1/wake/ghost2", stranger, wakeHdr)
	h.srv.Audit.Close()
	data, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r AuditRecord
		json.Unmarshal([]byte(line), &r)
		got = append(got, r.Action+" "+r.Host)
	}
	want := "GET /v1/hosts |wake fabric-twin|wake nas|wake ghost1"
	if strings.Join(got, "|") != want {
		t.Errorf("records %q\nwant    %q", strings.Join(got, "|"), want)
	}
}
