//go:build openbsd

package main

// Real pledge(2)/unveil(2) confinement on OpenBSD via golang.org/x/sys/unix
// (security review C4). catsvc holds the ct_issuer signing key, so confining it
// is the highest-value sandbox: a bug here must not be able to exec, open new
// files, or read anything beyond what it needs. A pledge violation terminates
// the process with the offending syscall logged to /var/log/messages.

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
