package sshx

import "os"

// Windows OpenSSH has no ControlMaster; the directory only has to exist.
func checkOwner(os.FileInfo, string) error { return nil }
