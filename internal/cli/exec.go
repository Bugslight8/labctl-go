package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

// SystemExec runs argv attached to this terminal and returns its exit code. While it runs, labctl ignores Ctrl-C:
// the terminal delivers it to ssh too, and in an interactive shell it belongs to the remote program.
func SystemExec(ctx context.Context, argv []string) (int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// DefaultControlDir is ~/.cache/labctl: short enough for the 104-byte Unix socket path limit on macOS.
func DefaultControlDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "labctl")
}
