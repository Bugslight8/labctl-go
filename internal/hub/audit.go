package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditRecord is one line of audit.jsonl: every wake, allowed or not, and every refused request.
type AuditRecord struct {
	Time   time.Time `json:"time"`
	Login  string    `json:"login,omitempty"`
	Device string    `json:"device,omitempty"`
	Addr   string    `json:"addr,omitempty"`
	Action string    `json:"action"`
	Host   string    `json:"host,omitempty"`
	Result string    `json:"result"`
}

// Audit appends records to <dir>/audit.jsonl. The directory is 0700 and the file 0600: the log names devices and
// logins, so only the owner reads it.
type Audit struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// StateDir is ~/.local/state/labctl, where the hub keeps its audit log and its own log.
func StateDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "labctl")
}

// OpenAudit opens (or creates) dir/audit.jsonl for appending, tightening the modes of an existing dir or file.
func OpenAudit(dir string, now func() time.Time) (*Audit, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	return &Audit{f: f, now: now}, nil
}

// Log writes one record; a write failure goes to stderr, because an action must not fail just because of its log.
func (a *Audit) Log(r AuditRecord) {
	r.Time = a.now()
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "labctl hub: audit:", err)
	}
}

// Close closes the file.
func (a *Audit) Close() error { return a.f.Close() }
