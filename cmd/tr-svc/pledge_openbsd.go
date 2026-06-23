//go:build openbsd

package main

import (
	"log"

	"golang.org/x/sys/unix"
)

func pledge(promises string) error { return unix.PledgePromises(promises) }

func unveil(path, perms string) {
	if err := unix.Unveil(path, perms); err != nil {
		log.Printf("unveil %s (%s): %v", path, perms, err)
	}
}

func unveilLock() {
	if err := unix.UnveilBlock(); err != nil {
		log.Printf("unveil lock: %v", err)
	}
}
