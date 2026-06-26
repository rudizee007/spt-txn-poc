//go:build openbsd

package main

// Real pledge(2)/unveil(2) confinement on OpenBSD via golang.org/x/sys/unix.
// The verify role holds NO signing key, only a read-only Trust Registry
// snapshot, so its sandbox is maximal: pledge "stdio rpath inet" omits wpath and
// cpath, meaning the process physically cannot write to disk or mutate the
// registry. A pledge violation terminates the process with the offending syscall
// logged to /var/log/messages.

import (
	"log"

	"golang.org/x/sys/unix"
)

func pledge(promises string) error {
	return unix.PledgePromises(promises)
}

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
