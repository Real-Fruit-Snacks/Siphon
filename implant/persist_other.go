//go:build !windows

package main

import (
	"siphon/shared"
)

// executePersist is a no-op on non-Windows platforms.
func executePersist(task *shared.Task) shared.TaskResult {
	return shared.TaskResult{TaskID: task.ID, Success: false, Output: "persist not supported on this platform"}
}

// executeUnpersist is a no-op on non-Windows platforms.
func executeUnpersist(task *shared.Task) shared.TaskResult {
	return shared.TaskResult{TaskID: task.ID, Success: false, Output: "unpersist not supported on this platform"}
}
