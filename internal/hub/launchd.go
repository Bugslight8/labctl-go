package hub

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Label is the launchd job name.
const Label = "com.labctl.hub"

// servicePath: launchd starts jobs with a bare PATH that lacks the tailscale CLI (Homebrew or the standalone app).
const servicePath = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// Plist is the LaunchAgent that runs `<exe> hub` at login and restarts it whenever it exits.
func Plist(exe, hostsPath, stateDir string) string {
	log := xmlText(filepath.Join(stateDir, "hub.log"))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlText(exe) + `</string>
		<string>hub</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>LABCTL_HOSTS</key>
		<string>` + xmlText(hostsPath) + `</string>
		<key>PATH</key>
		<string>` + servicePath + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>` + log + `</string>
	<key>StandardErrorPath</key>
	<string>` + log + `</string>
</dict>
</plist>
`
}

// Launchd installs and removes the hub's LaunchAgent in the user's GUI session.
type Launchd struct {
	Dir string // ~/Library/LaunchAgents
	UID int
	Run func(args ...string) error // runs launchctl
}

// NewLaunchd is the real one for this user.
func NewLaunchd() *Launchd {
	home, _ := os.UserHomeDir()
	return &Launchd{
		Dir: filepath.Join(home, "Library", "LaunchAgents"),
		UID: os.Getuid(),
		Run: func(args ...string) error {
			out, err := exec.Command("launchctl", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("launchctl %v: %v: %s", args, err, bytes.TrimSpace(out))
			}
			return nil
		},
	}
}

func (l *Launchd) plist() string { return filepath.Join(l.Dir, Label+".plist") }

// Install writes the plist and (re)loads it. When launchd refuses the GUI domain (an ssh session with nobody logged
// in at the screen), the plist stays in place, loads at the next login, and the message says how to load it now.
func (l *Launchd) Install(exe, hostsPath, stateDir string) (string, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(l.plist(), []byte(Plist(exe, hostsPath, stateDir)), 0o644); err != nil {
		return "", err
	}
	if err := os.Chmod(l.plist(), 0o644); err != nil {
		return "", err
	}
	domain := fmt.Sprintf("gui/%d", l.UID)
	_ = l.Run("bootout", domain+"/"+Label) // not loaded yet is fine
	if err := l.Run("bootstrap", domain, l.plist()); err != nil {
		return fmt.Sprintf("wrote %s, but launchd did not load it (%v).\nIt starts at the next login; to start it now, "+
			"from a terminal on the Mac itself: launchctl load -w %s", l.plist(), err, l.plist()), nil
	}
	return fmt.Sprintf("installed %s: the hub starts at login and restarts if it stops (log: %s)",
		l.plist(), filepath.Join(stateDir, "hub.log")), nil
}

// notLoaded reports whether a launchctl error only means the job was not loaded.
func notLoaded(err error) bool {
	s := err.Error()
	return strings.Contains(s, "No such process") || strings.Contains(s, "Could not find service")
}

// Uninstall stops the job and removes the plist. Not installed is not an error; any other launchctl failure is.
func (l *Launchd) Uninstall() error {
	if err := l.Run("bootout", fmt.Sprintf("gui/%d/%s", l.UID, Label)); err != nil && !notLoaded(err) {
		return err
	}
	if err := os.Remove(l.plist()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
