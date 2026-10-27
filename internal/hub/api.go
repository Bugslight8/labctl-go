package hub

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Bugslight8/labctl/internal/inventory"
	"github.com/Bugslight8/labctl/internal/wol"
)

const wakeInterval = 10 * time.Second

// Server is the hub's HTTP API. Every request passes the CSRF guard, then the Authorizer.
type Server struct {
	Inv      *inventory.Inventory
	Mon      *Monitor
	Auth     *Authorizer
	Audit    *Audit
	SendWOL  func(mac net.HardwareAddr, addr string) error
	Now      func() time.Time
	LongPoll time.Duration // how long /v1/events waits for news

	mu       sync.Mutex
	lastWake map[string]time.Time
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

// EventsResponse is GET /v1/events. Last is the newest Seq the hub has, so the next poll asks since=Last.
type EventsResponse struct {
	Events []Event `json:"events"`
	Last   uint64  `json:"last"`
}

// Handler is the whole API: guard -> auth -> routes.
func (s *Server) Handler() http.Handler {
	s.Auth.OnDeny = func(r *http.Request, c Caller, reason string) {
		s.Audit.Log(AuditRecord{Login: c.Login, Device: c.Device, Addr: c.Addr, Action: r.Method + " " + r.URL.Path, Result: "denied: " + reason})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hosts", s.hosts)
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("POST /v1/wake/{name}", s.wake)
	return s.guard(s.Auth.Wrap(mux))
}

// guard refuses anything a web page could send: requests with an Origin header (browsers add it to cross-site and
// non-GET requests) and state-changing requests without the X-Labctl: 1 header (a page cannot set it without CORS,
// which the hub never grants).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refuse := r.Header.Get("Origin") != "" || (r.Method != http.MethodGet && r.Header.Get("X-Labctl") != "1")
		if refuse {
			s.Audit.Log(AuditRecord{Addr: r.RemoteAddr, Action: r.Method + " " + r.URL.Path, Result: "denied: browser-style request"})
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next.ServeHTTP(w, r)
	})
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
			Wakeable: h.MAC != "" && s.Inv.Relay != "", State: string(st.State), Since: st.Since, IP: st.IP, LastSeen: st.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	since, err := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since must be a number"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.LongPoll)
	defer cancel()
	ev := s.Mon.Wait(ctx, since)
	if ev == nil {
		ev = []Event{}
	}
	writeJSON(w, http.StatusOK, EventsResponse{Events: ev, Last: s.Mon.Last()})
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	c := CallerFrom(r.Context())
	rec := AuditRecord{Login: c.Login, Device: c.Device, Addr: c.Addr, Action: "wake", Host: r.PathValue("name")}
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
	if last, ok := s.lastWake[h.Name]; ok && s.Now().Sub(last) < wakeInterval {
		s.mu.Unlock()
		reply(http.StatusTooManyRequests, "woken less than 10 s ago")
		return
	}
	s.lastWake[h.Name] = s.Now()
	s.mu.Unlock()
	mac, _ := net.ParseMAC(h.MAC) // validated by inventory.Parse
	if err := s.SendWOL(mac, wol.Broadcast); err != nil {
		reply(http.StatusBadGateway, "send failed: "+err.Error())
		return
	}
	reply(http.StatusAccepted, "sent")
}
