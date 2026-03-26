package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/mikeshogin/seclint/pkg/classifier"
	"github.com/mikeshogin/seclint/pkg/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: seclint {rate|check|serve}\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  rate              Rate prompt content from stdin\n")
		fmt.Fprintf(os.Stderr, "  check --max-rating N  Check if prompt passes threshold (exit 0=pass, 1=fail)\n")
		fmt.Fprintf(os.Stderr, "  serve [port]      Start HTTP server (default: 8091)\n")
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

// loadPolicy reads .seclint.yaml from the working directory.
// Falls back to DefaultPolicy if the file is absent.
func loadPolicy() *config.Policy {
	cwd, err := os.Getwd()
	if err != nil {
		return config.DefaultPolicy()
	}
	policy, err := config.LoadFromDir(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load .seclint.yaml: %v\n", err)
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
