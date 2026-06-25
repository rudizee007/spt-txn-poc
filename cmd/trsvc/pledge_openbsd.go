//go:build openbsd

package main

// Real pledge(2)/unveil(2) confinement on OpenBSD via golang.org/x/sys/unix.
// These replace the previous no-op stubs (security review C4): the service is
// now actually sandboxed. pledge restricts the syscall set; unveil restricts the
// visible filesystem. A violation terminates the process with a logged syscall
// in /var/log/messages, which is how the minimal sets are tuned.

import (
	"log"

	"golang.org/x/sys/unix"
)

// pledge restricts this process to the given promise set. Called after all
// listeners are bound and keys/config are loaded, so the serving loop needs only
// a small set.
func pledge(promises string) error {
	return unix.PledgePromises(promises)
}

// unveil exposes a single path to the process with the given permissions
// ("r","w","c","x" combinations). After the first unveil call the filesystem is
// hidden by default; unveilLock finalizes the set.
func unveil(path, perms string) {
	if err := unix.Unveil(path, perms); err != nil {
		log.Printf("unveil %s (%s): %v", path, perms, err)
	}
}

// unveilLock finalizes the unveil set; no further unveil calls are permitted.
func unveilLock() {
	if err := unix.UnveilBlock(); err != nil {
		log.Printf("unveil lock: %v", err)
	}
}

// withTightUmask runs fn with the process umask set to 0o177 (clears group/
// other and the owner-execute bit), restoring the previous umask afterwards.
// Used to bind the admin Unix socket so the node is *born* mode 0600 with no
// TOCTOU window between Listen and Chmod (security review SVC-2). unix.Umask
// is OpenBSD-only here; the non-OpenBSD stub is a plain passthrough.
func withTightUmask(fn func()) {
	old := unix.Umask(0o177)
	defer unix.Umask(old)
	fn()
}
