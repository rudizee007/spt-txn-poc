//go:build !openbsd

package main

// Stub implementations for non-OpenBSD builds (development on Linux/macOS).
// pledge and unveil are no-ops outside OpenBSD.

func pledge(_ string) error  { return nil }
func unveil(_, _ string)     {}
func unveilLock()             {}
