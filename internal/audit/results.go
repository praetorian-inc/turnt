// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"fmt"
	"strings"
	"time"
)

// Severity represents the security impact of a finding.
type Severity int

const (
	SeverityInfo     Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ColorString returns the severity with ANSI color codes.
func (s Severity) ColorString() string {
	switch s {
	case SeverityInfo:
		return "\033[36mINFO\033[0m" // cyan
	case SeverityLow:
		return "\033[34mLOW\033[0m" // blue
	case SeverityMedium:
		return "\033[33mMEDIUM\033[0m" // yellow
	case SeverityHigh:
		return "\033[31mHIGH\033[0m" // red
	case SeverityCritical:
		return "\033[1;31mCRITICAL\033[0m" // bold red
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single audit finding.
type Finding struct {
	ID          string
	Name        string
	Severity    Severity
	Description string
	Evidence    string
	Remediation string
	Timestamp   time.Time
}

// ScanResult represents the result of probing a single target address.
type ScanResult struct {
	Address  string
	Label    string
	Allowed  bool
	Error    string
	ErrCode  int
}

// AuditReport collects all findings from an audit run.
type AuditReport struct {
	Target    string
	StartTime time.Time
	EndTime   time.Time
	Findings  []Finding
}

// AddFinding appends a finding to the report.
func (r *AuditReport) AddFinding(f Finding) {
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
	r.Findings = append(r.Findings, f)
}

// PrintSummary outputs a formatted summary to stdout.
func (r *AuditReport) PrintSummary() {
	fmt.Printf("\n=== Audit Summary: %s ===\n", r.Target)
	fmt.Printf("Duration: %s\n", r.EndTime.Sub(r.StartTime).Round(time.Second))

	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	fmt.Printf("Findings: %d total", len(r.Findings))
	if c := counts[SeverityCritical]; c > 0 {
		fmt.Printf(" | %d Critical", c)
	}
	if c := counts[SeverityHigh]; c > 0 {
		fmt.Printf(" | %d High", c)
	}
	if c := counts[SeverityMedium]; c > 0 {
		fmt.Printf(" | %d Medium", c)
	}
	if c := counts[SeverityLow]; c > 0 {
		fmt.Printf(" | %d Low", c)
	}
	if c := counts[SeverityInfo]; c > 0 {
		fmt.Printf(" | %d Info", c)
	}
	fmt.Println()
}

// PrintFindings outputs detailed findings to stdout.
func (r *AuditReport) PrintFindings() {
	for _, f := range r.Findings {
		fmt.Printf("\n--- [%s] %s [%s] ---\n", f.ID, f.Name, f.Severity.ColorString())
		fmt.Printf("Description: %s\n", f.Description)
		if f.Evidence != "" {
			fmt.Printf("Evidence:\n%s\n", indent(f.Evidence, "  "))
		}
		if f.Remediation != "" {
			fmt.Printf("Remediation: %s\n", f.Remediation)
		}
	}
}

// PrintScanTable outputs a formatted table of scan results.
func PrintScanTable(results []ScanResult) {
	maxAddr := len("Address")
	maxLabel := len("Label")
	for _, r := range results {
		if len(r.Address) > maxAddr {
			maxAddr = len(r.Address)
		}
		if len(r.Label) > maxLabel {
			maxLabel = len(r.Label)
		}
	}

	fmt.Printf("\n%-*s  %-*s  %s\n", maxAddr, "Address", maxLabel, "Label", "Result")
	fmt.Printf("%s  %s  %s\n", strings.Repeat("-", maxAddr), strings.Repeat("-", maxLabel), "------")

	for _, r := range results {
		status := "\033[32mALLOWED\033[0m" // green
		if !r.Allowed {
			status = "\033[31mDENIED\033[0m" // red
			if r.Error != "" {
				status = fmt.Sprintf("\033[31mDENIED\033[0m (%s)", r.Error)
			}
		}
		fmt.Printf("%-*s  %-*s  %s\n", maxAddr, r.Address, maxLabel, r.Label, status)
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
