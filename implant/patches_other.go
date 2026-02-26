//go:build !windows

package main

// applyEvasions is a no-op on non-Windows platforms.
func applyEvasions() {}
