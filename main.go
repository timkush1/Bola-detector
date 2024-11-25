package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// LogEntry struct
type LogEntry struct {
	Req struct {
		URL        string                 `json:"url"`
		QSParams   map[string]interface{} `json:"qs_params"`
		Headers    map[string][]string    `json:"headers"`
		ReqBodyLen int                    `json:"req_body_len"`
	} `json:"req"`
	Rsp struct {
		StatusClass string `json:"status_class"`
		RspBodyLen  int    `json:"rsp_body_len"`
	} `json:"rsp"`
}

// PotentialBolaAttack represents a detected BOLA attack
type PotentialBolaAttack struct {
	URL            string
	QueryParams    map[string]interface{}
	AuthToken      string
	StatusClass    string
	Reason         string
}

// ParseLogFile reads and parses the access-log file line by line
func ParseLogFile(filePath string) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var logEntries []LogEntry
	scanner := bufio.NewScanner(file)

	// Parse each line as a JSON object
	for scanner.Scan() {
		var entry LogEntry
		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("failed to parse JSON line: %w", err)
		}
		// fmt.Printf("Parsed LogEntry: %+v\n", entry) // Debug: Print the unmarshaled LogEntry
		logEntries = append(logEntries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return logEntries, nil
}

func DetectBolaAttacks(logEntries []LogEntry) []PotentialBolaAttack {
	var bolaAttacks []PotentialBolaAttack
	invalidRequests := make(map[string]map[string]int)         // Tracks 4xx responses per root URL for each authToken
	consecutiveFailures := make(map[string]map[string]int)     // Tracks consecutive 4xx failures per root URL for each authToken
	authTokenPatterns := make(map[string][]string)             // Tracks user_id patterns per authToken

	for _, entry := range logEntries {
		// Extract Auth Token
		headers := entry.Req.Headers
		authHeader := headers["Authorization"]
		if len(authHeader) == 0 {
			continue
		}
		authToken := strings.TrimPrefix(authHeader[0], "Bearer ")

		// Extract root URL
		rootURL := strings.Split(entry.Req.URL, "?")[0]

		// Extract user_id
		userIDRaw := entry.Req.QSParams["user_id"]
		userID := fmt.Sprintf("%v", userIDRaw) // Convert the user_id to a string for simplicity

		// Initialize maps for authToken if not already present
		if _, exists := invalidRequests[authToken]; !exists {
			invalidRequests[authToken] = make(map[string]int)
			consecutiveFailures[authToken] = make(map[string]int)
		}

		// Track invalid requests per root URL
		if entry.Rsp.StatusClass == "4xx" {
			invalidRequests[authToken][rootURL]++
			consecutiveFailures[authToken][rootURL]++ // Increment consecutive failures for this root URL

			// Trigger BOLA detection for excessive invalid requests
			if invalidRequests[authToken][rootURL] > 4 {
				bolaAttacks = append(bolaAttacks, PotentialBolaAttack{
					URL:         entry.Req.URL,
					QueryParams: entry.Req.QSParams,
					AuthToken:   authToken,
					StatusClass: entry.Rsp.StatusClass,
					Reason:      fmt.Sprintf("Excessive 4xx responses targeting root URL '%s'", rootURL),
				})
			}

			// Trigger BOLA detection for consecutive failures (if failures are >2 and is the same root URL)
			if consecutiveFailures[authToken][rootURL] > 1 {
				bolaAttacks = append(bolaAttacks, PotentialBolaAttack{
					URL:         entry.Req.URL,
					QueryParams: entry.Req.QSParams,
					AuthToken:   authToken,
					StatusClass: entry.Rsp.StatusClass,
					Reason:      fmt.Sprintf("Alert! Multiple consecutive 4xx responses (>1) for root URL '%s'", rootURL),
				})
			}
		} else {
			// Reset consecutive if successful request
			consecutiveFailures[authToken][rootURL] = 0
		}

		// Detect enumeration patterns
		authTokenPatterns[authToken] = append(authTokenPatterns[authToken], userID)
		if isSequentialPattern(authTokenPatterns[authToken]) {
			bolaAttacks = append(bolaAttacks, PotentialBolaAttack{
				URL:         entry.Req.URL,
				QueryParams: entry.Req.QSParams,
				AuthToken:   authToken,
				StatusClass: entry.Rsp.StatusClass,
				Reason:      "Sequential user_id pattern indicating enumeration",
			})
		}
	}

	return bolaAttacks
}


// checks if sequence of userID calls 
func isSequentialPattern(userIDs []string) bool {
	if len(userIDs) < 3 {
		return false
	}
	for i := 1; i < len(userIDs)-1; i++ {
		prev, next := userIDs[i-1], userIDs[i+1]
		if prev < userIDs[i] && userIDs[i] < next {
			return true // Increasing pattern
		}
		if prev > userIDs[i] && userIDs[i] > next {
			return true // Decreasing pattern
		}
	}
	return false
}



// OutputBola 
func OutputBola(bolaAttacks []PotentialBolaAttack) {
	if len(bolaAttacks) == 0 {
		fmt.Println("No potential BOLA attacks detected.")
		return
	}

	fmt.Println("Potential BOLA Attacks Detected:")
	for _, attack := range bolaAttacks {
		fmt.Printf(
			"URL: %s, User ID: %v, AuthToken: %s, Status: %s, Reason: %s\n",
			attack.URL, attack.QueryParams["user_id"], attack.AuthToken, attack.StatusClass, attack.Reason,
		)
	}
}

func main() {
	filePath := "access.log"

	//Parse log file
	logEntries, err := ParseLogFile(filePath)
	if err != nil {
		log.Fatalf("Error parsing log file: %v", err)
	}
	//Detect BOLA attacks
	bolaAttacks := DetectBolaAttacks(logEntries)
	//BOLA report
	OutputBola(bolaAttacks)
}
