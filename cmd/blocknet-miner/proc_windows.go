//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
)

func setProcAttrs(cmd *exec.Cmd) {
	// no-op on windows
	_ = cmd
}

func interruptProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// Best-effort. Many programs ignore this on Windows.
	return cmd.Process.Signal(os.Interrupt)
}

func killProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func registerShutdown(fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		fn()
	}()
}
