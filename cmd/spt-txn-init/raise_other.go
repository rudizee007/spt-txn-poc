//go:build !unix

package main

import "os"

// raise, where a signal cannot be re-delivered to self: exit with the status
// shells use for an interrupted command.
func raise(os.Signal) { os.Exit(130) }
