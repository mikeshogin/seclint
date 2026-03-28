package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/mikeshogin/seclint/pkg/audit"
	"github.com/mikeshogin/seclint/pkg/classifier"
	"github.com/mikeshogin/seclint/pkg/config"
	"github.com/mikeshogin/seclint/pkg/report"
	"github.com/mikeshogin/seclint/pkg/threat"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: seclint {rate|check|serve|threats|audit|report}\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  rate                       Rate prompt content from stdin\n")
		fmt.Fprintf(os.Stderr, "  check --max-rating N       Check if prompt passes threshold (exit 0=pass, 1=fail)\n")
		fmt.Fprintf(os.Stderr, "  serve [port]               Start HTTP server (default: 8091)\n")
		fmt.Fprintf(os.Stderr, "  threats summary            Show threat feed statistics\n")
		fmt.Fprintf(os.Stderr, "  threats list [--limit N]   Show recent threats (default limit: 10)\n")
		fmt.Fprintf(os.Stderr, "  audit summary              Show audit log statistics\n")
		fmt.Fprintf(os.Stderr, "  audit tail [--limit N]     Show recent audit entries (default limit: 10)\n")
		fmt.Fprintf(os.Stderr, "  report [--format text]     Today's security report card (JSON default)\n")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "rate":
		runRate()
	case "check":
		runCheck()
	case "serve":
		runServe()
	case "threats":
		runThreats()
	case "audit":
		runAudit()
	case "report":
		runReport()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

// loadPolicy reads .seclint.yaml from the working directory and merges with
// the global policy (~/.seclint.yaml) via policy inheritance.
// Falls back to DefaultPolicy if neither file is present or readable.
func loadPolicy() *config.Policy {
	cwd, err := os.Getwd()
	if err != nil {
		return config.DefaultPolicy()
	}
	policy, err := config.LoadWithInheritance(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load policy: %v\n", err)
		return config.DefaultPolicy()
	}
	return policy
}

func runRate() {
	policy := loadPolicy()
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	result := classifier.ClassifyWithPolicy(string(input), policy)
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

func runCheck() {
	policy := loadPolicy()

	// Determine max rating: from policy file first, then --max-rating flag.
	maxRating := classifier.Rating16Plus
	if policy.Rating != "" {
		maxRating = parseRatingString(policy.Rating)
	}

	for i, arg := range os.Args[2:] {
		if arg == "--max-rating" && i+3 < len(os.Args) {
			val := os.Args[i+3]
			if n, err := strconv.Atoi(val); err == nil {
				maxRating = parseRatingInt(n)
			}
		}
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if classifier.IsSafeWithPolicy(string(input), maxRating, policy) {
		result := classifier.ClassifyWithPolicy(string(input), policy)
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
		os.Exit(0)
	} else {
		result := classifier.ClassifyWithPolicy(string(input), policy)
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stderr, string(out))
		os.Exit(1)
	}
}

func runThreats() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: seclint threats {summary|list [--limit N]}\n")
		os.Exit(1)
	}

	feed := threat.NewThreatFeed(threat.DefaultFeedPath())
	sub := os.Args[2]

	switch sub {
	case "summary":
		summary := feed.Summary()
		out, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(out))

	case "list":
		limit := 10
		for i, arg := range os.Args[3:] {
			if arg == "--limit" && i+4 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+4]); err == nil && n > 0 {
					limit = n
				}
			}
		}
		entries, err := feed.List(limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("No threats recorded yet.")
			return
		}
		out, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "Unknown threats subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runAudit() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: seclint audit {summary|tail [--limit N]}\n")
		os.Exit(1)
	}

	log := audit.NewAuditLog("")
	sub := os.Args[2]

	switch sub {
	case "summary":
		summary, err := log.Summary()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(out))

	case "tail":
		limit := 10
		for i, arg := range os.Args[3:] {
			if arg == "--limit" && i+4 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+4]); err == nil && n > 0 {
					limit = n
				}
			}
		}
		entries, err := log.Tail(limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("No audit entries recorded yet.")
			return
		}
		out, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "Unknown audit subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runServe() {
	policy := loadPolicy()
	port := "8091"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	fmt.Fprintf(os.Stderr, "seclint server on :%s\n", port)

	http.HandleFunc("/rate", makeHandleRate(policy))
	http.HandleFunc("/check", makeHandleCheck(policy))
	http.HandleFunc("/health", handleHealth)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func makeHandleRate(policy *config.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		result := classifier.ClassifyWithPolicy(string(body), policy)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func makeHandleCheck(policy *config.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		// Default from policy, override via query param
		maxRating := classifier.Rating16Plus
		if policy.Rating != "" {
			maxRating = parseRatingString(policy.Rating)
		}
		if maxRatingStr := r.URL.Query().Get("max_rating"); maxRatingStr != "" {
			if n, err := strconv.Atoi(maxRatingStr); err == nil {
				maxRating = parseRatingInt(n)
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		result := classifier.ClassifyWithPolicy(string(body), policy)
		safe := classifier.IsSafeWithPolicy(string(body), maxRating, policy)

		response := map[string]interface{}{
			"result": result,
			"safe":   safe,
		}

		w.Header().Set("Content-Type", "application/json")
		if !safe {
			w.WriteHeader(http.StatusForbidden)
		}
		json.NewEncoder(w).Encode(response)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"status":"ok"}`))
}

func parseRatingString(s string) classifier.Rating {
	switch s {
	case "6+":
		return classifier.Rating6Plus
	case "12+":
		return classifier.Rating12Plus
	case "16+":
		return classifier.Rating16Plus
	case "18+":
		return classifier.Rating18Plus
	default:
		return classifier.Rating16Plus
	}
}

func parseRatingInt(n int) classifier.Rating {
	switch {
	case n <= 6:
		return classifier.Rating6Plus
	case n <= 12:
		return classifier.Rating12Plus
	case n <= 16:
		return classifier.Rating16Plus
	default:
		return classifier.Rating18Plus
	}
}

func runReport() {
	formatText := false
	for _, arg := range os.Args[2:] {
		if arg == "--format" {
			// handled below
		} else if arg == "text" {
			formatText = true
		}
	}
	// Also handle --format=text style
	for _, arg := range os.Args[2:] {
		if arg == "--format=text" {
			formatText = true
		}
	}

	card, err := report.GenerateReportCard("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		os.Exit(1)
	}

	if formatText {
		fmt.Print(report.FormatText(card))
	} else {
		out, _ := json.MarshalIndent(card, "", "  ")
		fmt.Println(string(out))
	}
}
