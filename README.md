# BOLA Attack Detection System

## Overview
This application is designed to parse access logs and detect potential **BOLA (Broken Object Level Authorization)** attacks. The system identifies malicious patterns such as excessive failed requests, enumeration attempts, and brute-force attacks targeting specific resources. It processes logs in JSON format and generates detailed reports of suspicious activity.

---

## Features
### 1. **Parsing Access Logs**
   - Reads and parses logs in JSON format line by line.
   - Extracts key information such as:
     - Request URL and query parameters (`qs_params`).
     - Headers (e.g., `Authorization` token).
     - Response details (`status_class` and `rsp_body_len`).

### 2. **Detection Mechanisms**
#### **Excessive Failed Requests**
   - Tracks the number of `4xx` responses for each **authentication token** (`authToken`) per root URL.
   - Flags a root URL when more than 4 failed requests occur from the same token.

#### **Consecutive Failures**
   - Monitors consecutive `4xx` failures for each root URL and authentication token.
   - Triggers an alert when more than 1 consecutive failure occurs for the same root URL.

#### **patterns Detection**
   - Tracks patterns in `user_id` query parameters to detect sequential enumeration attempts.
   - Detects both increasing and decreasing sequences in `user_id` values, which could indicate probing for valid identifiers.

### 3. **Reporting**
   - Outputs a summary of detected attacks, including:
     - Root URL targeted.
     - Authentication token (`authToken`) involved.
     - Specific reasons for flagging (e.g., excessive failures, enumeration patterns).

---

## How It Works
1. **Log Parsing**:
   - Reads the log file line by line.
   - Decodes each line as a JSON object into a `LogEntry` structure.

2. **BOLA Detection**:
   - Evaluates each log entry using various detection rules:
     - Excessive invalid requests (`4xx`) for the same root URL.
     - Consecutive failures for the same root URL.
     - Sequential patterns in user ID query parameters.

3. **Output Report**:
   - Generates a summary of potential attacks.

### My Suggestion: Timestamp Analysis

Adding timestamps to the access logs would significantly enhance the detection capabilities. With timestamps, we could:
- Detect suspicious patterns based on the rate of requests (e.g., multiple `4xx` failures within a short period).
- Identify bursts of activity that might indicate brute-force or enumeration attacks.
- Better analyze token usage over time to flag anomalies.

Currently, the absence of timestamps limits the ability to correlate events with time, but the implemented logic still provides strong detection mechanisms within the given constraints.




