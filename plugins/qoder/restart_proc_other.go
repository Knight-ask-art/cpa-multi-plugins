//go:build !windows

package main

import "syscall"

// On Unix the helper just leaves the process group so a signal aimed at the
// host's group does not take it down. Automatic restart is Windows-only at the
// scheduling layer; this keeps the package cross-compiling.
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
