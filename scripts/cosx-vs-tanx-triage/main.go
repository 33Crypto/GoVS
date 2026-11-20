// Command cosx-vs-tanx-triage summarizes CodeQL SARIF for the
// cosx-vs-tanx-triage pipeline. It is a Go port of scripts/tanx.ts.
//
// It reads SARIF results plus extraction and build logs, writes a markdown
// summary to GITHUB_STEP_SUMMARY, and also writes that summary to disk so
// the workflow can upload it with the SARIF artifact.
//
//	go run ./scripts/cosx-vs-tanx-triage \
//	  --sarif codeql-results \
//	  --summary codeql-results/tanx-summary.md \
//	  --logs "$RUNNER_TEMP/codeql_databases"
//
// Standard library only. Findings do not fail the process. A missing or
// unreadable SARIF is reported in the summary and exits with code 2, so a
// broken analysis is never mistaken for a clean one.
//
// The output is meant to match tanx.ts byte for byte. To get there, the
// package reproduces the JavaScript behaviour tanx.ts relies on (see
// jscompat.go and jsonparse.go): JSON.parse with its error messages and key
// order, UTF-16 string lengths, JavaScript whitespace and regex semantics,
// Node's path helpers, Number-to-string conversion, and localeCompare
// ordering for ASCII paths.
//
// Layout: main.go (CLI and entry point), sarif.go (SARIF reading and
// findings), logs.go (log scanning and database notes), summary.go
// (markdown generation).
package main

import (
	"fmt"
	"os"
)

type cli struct {
	sarif   string
	summary string
	logs    string
	hasLogs bool
}

const usage = "Usage: go run ./scripts/cosx-vs-tanx-triage --sarif <file-or-dir> --summary <markdown> [--logs <dir>]\n"

func parseArgs(argv []string) cli {
	c := cli{
		sarif:   "codeql-results",
		summary: nodeJoin("codeql-results", "tanx-summary.md"),
	}
	if runnerTemp := os.Getenv("RUNNER_TEMP"); runnerTemp != "" {
		c.logs, c.hasLogs = nodeJoin(runnerTemp, "codeql_databases"), true
	}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		switch {
		case arg == "--sarif" && next != "":
			c.sarif = next
			i++
		case arg == "--summary" && next != "":
			c.summary = next
			i++
		case arg == "--logs" && next != "":
			c.logs, c.hasLogs = next, true
			i++
		case arg == "--help" || arg == "-h":
			os.Stdout.WriteString(usage)
			os.Exit(0)
		default:
			throwError("Error", "Unknown argument: %s", arg)
		}
	}
	return c
}

func run() int {
	c := parseArgs(os.Args[1:])
	result := summarize(c)
	markdown := toOutput(result.markdown)
	dir := nodeDirname(nodeResolve(c.summary))
	if err := os.MkdirAll(dir, 0o777); err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "mkdir", dir))
	}
	if err := os.WriteFile(c.summary, []byte(markdown), 0o666); err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "open", c.summary))
	}
	if stepSummary := os.Getenv("GITHUB_STEP_SUMMARY"); stepSummary != "" {
		f, err := os.OpenFile(stepSummary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
		if err == nil {
			_, err = f.WriteString(markdown)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			throwError("Error", "%s", nodeFsMessage(err, "open", stepSummary))
		}
	}
	os.Stdout.WriteString(markdown)
	fmt.Fprintf(os.Stdout, "tanx: %d finding(s), %d diagnostic line(s)\n", result.findingCount, result.diagnosticCount)
	if !result.analysisOk {
		return 2
	}
	return 0
}

func main() {
	code := func() (code int) {
		defer func() {
			if r := recover(); r != nil {
				je, ok := r.(*jsError)
				if !ok {
					panic(r)
				}
				fmt.Fprintf(os.Stderr, "%s: %s\n", je.name, je.message)
				code = 1
			}
		}()
		return run()
	}()
	os.Exit(code)
}
