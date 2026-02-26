package main

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"time"
)

// Build-time variables set via -ldflags
var (
	c2Host    = "https://127.0.0.1:443"
	sleepSec  = "5"
	serverPK  = ""
	beaconURL = "/api/news"
	submitURL = "/api/submit"
	killDate  = "" // format: 2006-01-02 — implant exits silently after this date
	authToken = "" // pre-shared HMAC key for C2 endpoint authentication
)

func GetSleepDuration() time.Duration {
	n, err := strconv.Atoi(sleepSec)
	if err != nil || n <= 0 {
		return 5 * time.Second
	}
	return time.Duration(n) * time.Second
}

func GetJitter() time.Duration {
	base := GetSleepDuration()
	if base <= 0 {
		return 0
	}
	jitterMax := uint64(base) * 50 / 100 // max 50% jitter
	if jitterMax == 0 {
		return 0
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	n := binary.BigEndian.Uint64(b)
	return time.Duration(n % jitterMax)
}
