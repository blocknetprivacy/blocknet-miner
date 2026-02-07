//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func setProcAttrs(cmd *exec.Cmd) {
	// Put the daemon into its own process group so we can interrupt/kill the whole group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func interruptProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// Negative PID = send to process group.
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
}

func killProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func registerShutdown(fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		fn()
	}()
}
