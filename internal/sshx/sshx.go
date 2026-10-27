// Package sshx builds the ssh command lines labctl runs: one shared connection per host, quoted remote commands.
package sshx

import (
	"fmt"
	"os"
	"strings"

	"github.com/Bugslight8/labctl/internal/inventory"
)

// Options keep one connection per host open for 10 minutes, so later commands skip the handshake, and drop a dead
// connection (laptop asleep, network change) in about 10 s instead of hanging.
func Options(controlDir string) []string {
	return []string{
		"-o", "ConnectTimeout=10",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + controlDir + "/cm-%C",
		"-o", "ControlPersist=10m",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
	}
}

// Target is user@tailnet, or just the tailnet name when no user is set.
func Target(h inventory.Host) string {
	if h.User != "" {
		return h.User + "@" + h.Tailnet
	}
	return h.Tailnet
}

// Argv is the ssh command that runs remote on h; tty allocates a terminal (interactive shells, tmux).
// remote = "" opens a login shell. The "--" ends ssh's options: OpenSSH keeps parsing options after the host, so
// without it a one-argument command such as -oProxyCommand=... would run on this machine.
func Argv(h inventory.Host, controlDir, remote string, tty bool) []string {
	argv := append([]string{"ssh"}, Options(controlDir)...)
	if tty {
		argv = append(argv, "-t")
	} else {
		argv = append(argv, "-T")
	}
	argv = append(argv, "--", Target(h))
	if remote != "" {
		argv = append(argv, remote)
	}
	return argv
}

// OffArgv closes h's shared connection.
func OffArgv(h inventory.Host, controlDir string) []string {
	return append(append([]string{"ssh"}, Options(controlDir)...), "-O", "exit", "--", Target(h))
}

// ShellCommand attaches h's tmux session or creates it, falling back to a login shell when tmux is missing.
// Empty when the host has no tmux session: ssh then opens a plain login shell.
func ShellCommand(h inventory.Host) string {
	if h.Tmux == "" {
		return ""
	}
	s := quote(h.Tmux)
	return "tmux attach -t " + s + " 2>/dev/null || tmux new -s " + s + " || exec \"$SHELL\" -l"
}

// RemoteCommand: one argument is a shell string the user wrote ('make a && make b'); several are quoted one by one,
// so `labctl host git commit -m "fix bgp"` arrives intact.
func RemoteCommand(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return Quote(args)
}

// Quote makes each argument one POSIX shell word: wrapped in single quotes; an embedded single quote closes the
// quoting, is backslash-escaped, and reopens it.
func Quote(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quote(a)
	}
	return strings.Join(q, " ")
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// EnsureControlDir creates dir with mode 0700, or checks that an existing one is a directory that only this user
// owns and can write: anyone else who could write there could plant a socket and see every command we send.
func EnsureControlDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return checkPrivate(fi, dir)
}
