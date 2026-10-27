//go:build !windows

package sshx

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwner(fi os.FileInfo, dir string) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not you", dir, st.Uid)
	}
	return nil
}
