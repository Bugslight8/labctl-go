//go:build !windows

package sshx

import (
	"fmt"
	"os"
	"syscall"
)

func checkPrivate(fi os.FileInfo, dir string) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %v: other users can reach the SSH sockets; run chmod 700 %s", dir, fi.Mode().Perm(), dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not you", dir, st.Uid)
	}
	return nil
}
