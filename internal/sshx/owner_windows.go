package sshx

import "os"

// Windows reports every directory as mode 0777 and OpenSSH there has no ControlMaster sockets: the directory only
// has to exist.
func checkPrivate(os.FileInfo, string) error { return nil }
