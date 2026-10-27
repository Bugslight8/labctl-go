package hub

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/wol"
)

const (
	wakeInterval   = 10 * time.Second
	denyLogEvery   = time.Minute // a refused address is logged once per minute, so refusals cannot fill the disk
	maxLoggedField = 128         // bytes of a request path that reach the audit log
)

// Server is the hub's HTTP API. Every request passes the browser guard, then the Authorizer.
type Server struct {
	Inv          *inventory.Inventory
	Mon          *Monitor
	Auth         *Authorizer
	Audit        *Audit
	SendWOL      func(mac net.HardwareAddr, addr string) error
	Now          func() time.Time
	LongPoll     time.Duration // how long /v1/events waits for news
	AllowedHosts []string      // Host header names the hub answers to: its Tailscale IPs and MagicDNS names

	mu         sync.Mutex
	lastWake   map[string]time.Time
	lastDenied map[string]time.Time
}

// HostInfo is one host in GET /v1/hosts. It never carries the MAC: clients wake through the hub.
type HostInfo struct {
	Name     string    `json:"name"`
	Tailnet  string    `json:"tailnet"`
	User     string    `json:"user,omitempty"`
	OS       string    `json:"os,omitempty"`
	Tmux     string    `json:"tmux"`
	Wakeable bool      `json:"wakeable"`
	State    string    `json:"state"`
	Since    time.Time `json:"since"`
	IP       string    `json:"ip,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// HostsResponse is GET /v1/hosts.
type HostsResponse struct {
	Relay string     `json:"relay"`
	Hosts []HostInfo `json:"hosts"`
}

// EventsResponse is GET /v1/events. Last is the newest Seq, so the next poll asks since=Last&boot=Boot. A Boot that
// differs from the client's means the hub restarted and numbering began again: start over from since=0.
type EventsResponse struct {
	Events []Event `json:"events"`
	Last   uint64  `json:"last"`
	Boot   string  `json:"boot"`
}

// Handler is the whole API: guard -> auth -> routes.
func (s *Server) Handler() http.Handler {
	s.Auth.OnDeny = func(r *http.Request, c Caller, reason string) { s.deny(r, c, reason) }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hosts", s.hosts)
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("POST /v1/wake/{name}", s.wake)
	return s.guard(s.Auth.Wrap(mux))
}

// guard refuses anything a web page could send. Browsers add Origin to cross-site and non-GET requests, and
// Sec-Fetch-* to every request; a page cannot add X-Labctl without CORS, which the hub never grants. A DNS-rebinding
// page is same-origin and sends no Origin, but its Host is its own domain, so only the hub's own names pass.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := ""
		switch {
		case !s.allowedHost(r.Host):
			reason = "unknown Host header"
		case r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-Mode") != "":
			reason = "browser request"
		case r.Method != http.MethodGet && r.Header.Get("X-Labctl") != "1":
			reason = "missing X-Labctl header"
		}
		if reason != "" {
			s.deny(r, Caller{Addr: addrOnly(r.RemoteAddr)}, reason)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(h string) bool {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	for _, a := range s.AllowedHosts {
		if strings.EqualFold(a, h) {
			return true
		}
	}
	return false
}

// deny audits a refusal: at most once per address per minute, with the path cut short.
func (s *Server) deny(r *http.Request, c Caller, reason string) {
	now := s.Now()
	s.mu.Lock()
	if s.lastDenied == nil || len(s.lastDenied) > 10000 {
		s.lastDenied = map[string]time.Time{}
	}
	last, seen := s.lastDenied[c.Addr]
	if seen && now.Sub(last) < denyLogEvery {
		s.mu.Unlock()
		return
	}
	s.lastDenied[c.Addr] = now
	s.mu.Unlock()
	rec := AuditRecord{Login: c.Login, Device: c.Device, Addr: c.Addr, Action: clip(r.Method + " " + r.URL.Path), Result: "denied: " + reason}
	if name, ok := strings.CutPrefix(r.URL.Path, "/v1/wake/"); ok {
		rec.Action, rec.Host = "wake", clip(name)
	}
	s.Audit.Log(rec)
}

func clip(s string) string {
	if len(s) > maxLoggedField {
		return s[:maxLoggedField] + "..."
	}
	return s
}

// addrOnly is the IP of a host:port, or the input when it does not parse.
func addrOnly(remote string) string {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().String()
	}
	return clip(remote)
}

func (s *Server) hosts(w http.ResponseWriter, _ *http.Request) {
	states := map[string]HostState{}
	for _, h := range s.Mon.Hosts() {
		states[h.Name] = h
	}
	resp := HostsResponse{Relay: s.Inv.Relay, Hosts: []HostInfo{}}
	for _, h := range s.Inv.Hosts {
		st := states[h.Name]
		osName := st.OS
		if osName == "" {
			osName = h.OS
		}
		resp.Hosts = append(resp.Hosts, HostInfo{
			Name: h.Name, Tailnet: h.Tailnet, User: h.User, OS: osName, Tmux: h.Tmux,
			Wakeable: h.MAC != "", // the hub sends the packet itself: a MAC is all it needs
			State:    string(st.State), Since: st.Since, IP: st.IP, LastSeen: st.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := strconv.ParseUint(q.Get("since"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be a number"})
		return
	}
	if b := q.Get("boot"); b != "" && b != s.Mon.Boot {
		since = 0 // the client's numbers come from before a restart
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.LongPoll)
	defer cancel()
	ev, last := s.Mon.Wait(ctx, since)
	if ev == nil {
		ev = []Event{}
	}
	writeJSON(w, http.StatusOK, EventsResponse{Events: ev, Last: last, Boot: s.Mon.Boot})
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	c := CallerFrom(r.Context())
	rec := AuditRecord{Login: c.Login, Device: c.Device, Addr: c.Addr, Action: "wake", Host: clip(r.PathValue("name"))}
	reply := func(code int, result string) {
		rec.Result = result
		s.Audit.Log(rec)
		writeJSON(w, code, map[string]string{"result": result})
	}
	h, ok := s.Inv.Find(r.PathValue("name"))
	if !ok {
		reply(http.StatusNotFound, "unknown host")
		return
	}
	rec.Host = h.Name
	if h.MAC == "" {
		reply(http.StatusConflict, "no mac in the hub's hosts file")
		return
	}
	s.mu.Lock()
	if s.lastWake == nil {
		s.lastWake = map[string]time.Time{}
	}
	prev, had := s.lastWake[h.Name]
	if had && s.Now().Sub(prev) < wakeInterval {
		s.mu.Unlock()
		reply(http.StatusTooManyRequests, "woken less than 10 s ago")
		return
	}
	s.lastWake[h.Name] = s.Now()
	s.mu.Unlock()
	mac, _ := net.ParseMAC(h.MAC) // validated by inventory.Parse
	if err := s.SendWOL(mac, wol.Broadcast); err != nil {
		s.mu.Lock() // a failed send must not use up the slot: the retry should go out
		if had {
			s.lastWake[h.Name] = prev
		} else {
			delete(s.lastWake, h.Name)
		}
		s.mu.Unlock()
		reply(http.StatusBadGateway, "send failed: "+err.Error())
		return
	}
	reply(http.StatusAccepted, "sent")
}
