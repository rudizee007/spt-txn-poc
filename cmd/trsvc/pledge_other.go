//go:build !openbsd

package main

// Stub implementations for non-OpenBSD builds (development on Linux/macOS).
// pledge and unveil are no-ops outside OpenBSD.

func pledge(_ string) error { return nil }
func unveil(_, _ string)    {}
func unveilLock()           {}

// withTightUmask is a passthrough on non-OpenBSD: the admin socket's mode is
// still tightened by the explicit os.Chmod in main. unix.Umask is not portable
// to every OS the dev build targets, so this stub just runs fn (security review
// SVC-2 — the openbsd build gets the born-0600 guarantee).
func withTightUmask(fn func()) { fn() }
