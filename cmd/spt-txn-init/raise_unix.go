//go:build unix

package main

import (
	"os"
	"syscall"
	"time"
)

// raise re-delivers sig to this process with the default disposition restored,
// so the exit status is "killed by SIGINT" rather than an exit code that hides
// what happened. Delivery is asynchronous, so wait for it rather than racing
// it with os.Exit; if it somehow never arrives, exit non-zero anyway.
func raise(sig os.Signal) {
	if s, ok := sig.(syscall.Signal); ok {
		if err := syscall.Kill(syscall.Getpid(), s); err == nil {
			time.Sleep(2 * time.Second)
		}
	}
	os.Exit(130)
}
