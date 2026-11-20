// Extraction and build log scanning, plus CodeQL database notes.

package main

import (
	"os"
	"regexp"
	"strings"
)

var (
	reInterpreted  = regexp.MustCompile(`interpreted (diagnostic|problem|pathproblem|metric) query`)
	reDetails      = regexp.MustCompile(`\[details\]`)
	reColonLevel   = regexp.MustCompile(`:[` + jsWS + `]*(error|warning)[` + jsWS + `]`)
	reCompilerCode = regexp.MustCompile(`\b(error|warning)[` + jsWS + `]+(cs|msb)\d+`)
	reBuildOK      = regexp.MustCompile(`\bbuild succeeded\b`)
	reBuildFailed  = regexp.MustCompile(`\bbuild failed\b`)
	reCounts       = regexp.MustCompile(`\d+[` + jsWS + `]+(Error|Warning)\(s\)`)
	reNoSource     = regexp.MustCompile(`no source code (was )?seen`)
	reFailedToExt  = regexp.MustCompile(`failed to extract`)
	reBracketLevel = regexp.MustCompile(`\][` + jsWS + `]*(ERROR|WARNING)\b`)
	reSevError     = regexp.MustCompile(`error|failed|fatal`)
	reZeroErrors   = regexp.MustCompile(`0 Error\(s\)`)
	reSevWarning   = regexp.MustCompile(`warning`)
	reZeroWarnings = regexp.MustCompile(`0 Warning\(s\)`)
	reBuildMode    = regexp.MustCompile(`(?m)(?:^|[\r\x{2028}\x{2029}])buildMode:[` + jsWS + `]*([^` + jsWS + `]+)`)
	reLanguage     = regexp.MustCompile(`(?m)(?:^|[\r\x{2028}\x{2029}])primaryLanguage:[` + jsWS + `]*([^` + jsWS + `]+)`)
)

// findLogFiles lists the .log files next to the SARIF and, when a log
// directory is set, its .log and .txt files.
func findLogFiles(c cli) []string {
	logPaths := walk(c.sarif, func(name string) bool { return strings.HasSuffix(name, ".log") })
	if c.hasLogs {
		logPaths = append(logPaths, walk(c.logs, func(name string) bool {
			return strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".txt")
		})...)
	}
	return logPaths
}

// scanLogs adds log diagnostics and returns the database notes.
func (t *triage) scanLogs(c cli, logPaths []string) []string {
	for _, path := range logPaths {
		t.diagnostics = append(t.diagnostics, logDiagnostics(path)...)
	}

	var dbNotes []string
	if c.hasLogs && exists(c.logs) {
		dbNotes = databaseNotes(c.logs)
	}
	if c.hasLogs && !exists(c.logs) {
		t.diagnostics = append(t.diagnostics, diagnostic{"note", tanxSource(), "CodeQL database log directory was not found: " + c.logs})
	}
	return dbNotes
}

func readCapped(path string, maxBytes int64) string {
	info, err := os.Stat(path)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "stat", path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "open", path))
	}
	if size := info.Size(); size > maxBytes {
		start := size - maxBytes
		if start > int64(len(data)) {
			data = nil
		} else {
			data = data[start:]
		}
	}
	return fromUTF16(decodeUTF8(data))
}

func interestingLogLine(line string) bool {
	if utf16Len(line) > 500 {
		return false
	}
	lower := asciiLower(line)
	// CodeQL's own query-evaluation log names queries such as "Extraction error"
	// while describing a successful run. Those lines are not build failures.
	if reInterpreted.MatchString(lower) {
		return false
	}
	if reDetails.MatchString(lower) {
		return false
	}
	return reColonLevel.MatchString(lower) ||
		reCompilerCode.MatchString(lower) ||
		reBuildOK.MatchString(lower) ||
		reBuildFailed.MatchString(lower) ||
		reCounts.MatchString(line) ||
		reNoSource.MatchString(lower) ||
		reFailedToExt.MatchString(lower) ||
		reBracketLevel.MatchString(line)
}

func logDiagnostics(path string) []diagnostic {
	text := readCapped(path, 1_000_000)
	source := strValue(nodeBasename(path))
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		line := jsTrim(raw)
		if interestingLogLine(line) {
			lines = append(lines, line)
		}
	}
	var unique []string
	for _, line := range lines {
		if len(unique) == 0 || unique[len(unique)-1] != line {
			unique = append(unique, line)
		}
	}
	if len(unique) > 40 {
		unique = unique[:40]
	}
	out := make([]diagnostic, 0, len(unique))
	for _, line := range unique {
		lower := asciiLower(line)
		severity := "note"
		if reSevError.MatchString(lower) && !reZeroErrors.MatchString(line) {
			severity = "error"
		} else if reSevWarning.MatchString(lower) && !reZeroWarnings.MatchString(line) {
			severity = "warning"
		}
		if reBuildOK.MatchString(lower) {
			severity = "note"
		}
		out = append(out, diagnostic{severity: severity, source: source, message: line})
	}
	return out
}

func databaseNotes(root string) []string {
	var notes []string
	for _, path := range walk(root, func(name string) bool { return name == "codeql-database.yml" }) {
		text := readCapped(path, 100_000)
		parts := []string{nodeBasename(nodeDirname(path))}
		if m := reLanguage.FindStringSubmatch(text); m != nil {
			parts = append(parts, "language="+m[1])
		}
		if m := reBuildMode.FindStringSubmatch(text); m != nil {
			parts = append(parts, "buildMode="+m[1])
		}
		notes = append(notes, strings.Join(parts, " "))
	}
	return notes
}
