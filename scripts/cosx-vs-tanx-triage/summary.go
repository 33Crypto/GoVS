// Markdown summary generation.

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var severityRank = map[string]int{
	"error":   0,
	"warning": 1,
	"note":    2,
	"none":    3,
}

func rankOf(level string) int {
	if r, ok := severityRank[level]; ok {
		return r
	}
	return 4
}

var (
	reNewline = regexp.MustCompile(`\r?\n`)
)

func cell(v *value) string {
	s := requireString(v, "replace")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '`', '*', '_', '[', ']', '|':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return jsTrim(reNewline.ReplaceAllString(b.String(), " "))
}

func cellText(s string) string { return cell(strValue(s)) }

type summaryResult struct {
	markdown        string
	findingCount    int
	diagnosticCount int
	analysisOk      bool
}

// summarize runs the SARIF and log scans and renders the markdown summary.
func summarize(c cli) summaryResult {
	sarifPaths := findSarifFiles(c.sarif)
	logPaths := findLogFiles(c)
	t := &triage{}
	t.checkSarifRoot(c.sarif, len(sarifPaths))
	for _, path := range sarifPaths {
		t.readSarif(path)
	}
	dbNotes := t.scanLogs(c, logPaths)
	return render(t, sarifPaths, dbNotes)
}

// render sorts the findings and builds the markdown.
func render(t *triage, sarifPaths []string, dbNotes []string) summaryResult {
	findings, diagnostics, tools := t.findings, t.diagnostics, t.tools
	linesOfCode, unreadableSarif := t.linesOfCode, t.unreadableSarif

	lineNumber := func(line string) float64 {
		if line == "" {
			return 0
		}
		return stringToNumber(line)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank := rankOf(a.severity) - rankOf(b.severity); rank != 0 {
			return rank < 0
		}
		if f := localeCompare(a.file, b.file); f != 0 {
			return f < 0
		}
		return lineNumber(a.line)-lineNumber(b.line) < 0
	})

	var countOrder []string
	counts := map[string]int{}
	for _, f := range findings {
		key := strings.Replace(f.severity, " (suppressed)", "", 1)
		if _, ok := counts[key]; !ok {
			countOrder = append(countOrder, key)
		}
		counts[key]++
	}
	var countParts []string
	for _, level := range countOrder {
		countParts = append(countParts, fmt.Sprintf("%d %s", counts[level], level))
	}
	countText := strings.Join(countParts, ", ")

	var lines []string
	push := func(s string) { lines = append(lines, s) }
	push("## cosx-vs-tanx-triage")
	push("")
	push("### Analysis")
	push("")
	analysisOk := len(sarifPaths) > 0 && unreadableSarif == 0
	if analysisOk {
		push("- Analysis status: completed")
	} else {
		push("- Analysis status: FAILED (results missing or unreadable)")
	}
	push(fmt.Sprintf("- SARIF files: %d", len(sarifPaths)))
	if len(tools) > 0 {
		seen := map[string]bool{}
		var uniqueTools []string
		for _, t := range tools {
			key := sameValueZeroKey(t)
			if seen[key] {
				continue
			}
			seen[key] = true
			uniqueTools = append(uniqueTools, toStr(t))
		}
		push("- Tool: " + strings.Join(uniqueTools, ", "))
	}
	if countText != "" {
		push(fmt.Sprintf("- Findings: %d (%s)", len(findings), countText))
	} else {
		push(fmt.Sprintf("- Findings: %d", len(findings)))
	}
	if linesOfCode != nil {
		push("- Lines of code extracted: " + jsNumber(*linesOfCode))
	}
	if len(dbNotes) > 0 {
		push("- Database: " + strings.Join(dbNotes, "; "))
	}
	push("")
	push("### Findings")
	push("")
	switch {
	case !analysisOk:
		push("Analysis did not complete, so this is NOT a clean result. See extraction and build.")
	case len(findings) == 0:
		push("CodeQL reported no findings.")
	default:
		push("| Severity | Rule | Location | Message |")
		push("| --- | --- | --- | --- |")
		for _, f := range findings {
			location := f.file
			if f.line != "" {
				location = f.file + ":" + f.line
			}
			push(fmt.Sprintf("| %s | %s | %s | %s |", cellText(f.severity), cell(f.rule), cellText(location), cellText(f.message)))
		}
	}
	push("")
	push("### Extraction and build")
	push("")
	if len(diagnostics) == 0 {
		push("No extraction or build errors or warnings were recorded.")
	} else {
		shown := diagnostics
		if len(shown) > 60 {
			shown = shown[:60]
		}
		push("| Severity | Source | Message |")
		push("| --- | --- | --- |")
		for _, d := range shown {
			push(fmt.Sprintf("| %s | %s | %s |", cellText(d.severity), cell(d.source), cellText(d.message)))
		}
		if len(diagnostics) > len(shown) {
			push("")
			push(fmt.Sprintf("Showing %d of %d diagnostic lines.", len(shown), len(diagnostics)))
		}
	}
	push("")

	return summaryResult{
		markdown:        strings.Join(lines, "\n") + "\n",
		findingCount:    len(findings),
		diagnosticCount: len(diagnostics),
		analysisOk:      analysisOk,
	}
}
