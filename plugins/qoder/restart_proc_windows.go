//go:build windows

package main

import "syscall"

// detachedSysProcAttr keeps the launcher helper alive after CPA is killed.
//
// It must NOT set DETACHED_PROCESS, CREATE_NO_WINDOW, CREATE_NEW_PROCESS_GROUP
// or CREATE_BREAKAWAY_FROM_JOB (v0.8.73, measured): a console-less powershell
// started that way from inside the CPA process never runs its -File script —
// it is spawned, then exits without touching the log. The same command line
// with HideWindow alone works. The helper also only needs to survive the
// current process: start-pebrel.ps1 itself kills cli-proxy-api by name.
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
