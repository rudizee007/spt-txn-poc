//go:build !openbsd

package main

// No-ops outside OpenBSD (development on Linux/macOS).
func pledge(_ string) error { return nil }
func unveil(_, _ string)    {}
func unveilLock()           {}
