// SARIF discovery, parsing, and conversion into findings and diagnostics.

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type finding struct {
	severity string
	rule     *value
	file     string
	line     string
	message  string
}

type diagnostic struct {
	severity string
	source   *value
	message  string
}

// triage accumulates what the SARIF and log scans find.
type triage struct {
	findings        []finding
	diagnostics     []diagnostic
	tools           []*value
	linesOfCode     *float64
	unreadableSarif int
}

func tanxSource() *value { return strValue("tanx") }

var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"bin":          true,
	"obj":          true,
	"cache":        true,
	"trap":         true,
}

var (
	reSpaceRun    = regexp.MustCompile(`[` + jsWS + `]+`)
	reDriveLetter = regexp.MustCompile(`^/[A-Za-z]:`)
	reDiagRule    = regexp.MustCompile(`diagnostic|extractor|successfully-extracted`) // on asciiLower
	reExtracted   = regexp.MustCompile(`/diagnostics/successfully-extracted-files$`)
	reLinesOfCode = regexp.MustCompile(`/summary/lines-of-code$`)
)

func messageText(message *value) string {
	text := coalesce(coalesce(opt(message, "text"), opt(message, "markdown")), strValue(""))
	return jsTrim(reSpaceRun.ReplaceAllString(requireString(text, "replace"), " "))
}

func displayPath(uri string) string {
	path := jsTrim(uri)
	if strings.HasPrefix(path, "file://") {
		path = decodeURIComponent(path[len("file://"):])
		if reDriveLetter.MatchString(path) {
			path = path[1:]
		}
	}
	path = strings.ReplaceAll(path, "\\", "/")
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" && strings.HasPrefix(path, "/") {
		rel := nodeRelative(nodeResolve(workspace), path)
		if rel != "" && !strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, "/") {
			return strings.ReplaceAll(rel, "\\", "/")
		}
	}
	return path
}

func locationOf(result *value) (string, string) {
	places := append([]*value{}, iterate(coalesce(get(result, "locations"), &value{k: kArr}), "result.locations")...)
	places = append(places, iterate(coalesce(get(result, "relatedLocations"), &value{k: kArr}), "result.relatedLocations")...)
	for _, place := range places {
		physical := get(place, "physicalLocation")
		uri := opt(opt(physical, "artifactLocation"), "uri")
		if !truthy(uri) {
			continue
		}
		line := opt(opt(physical, "region"), "startLine")
		lineText := ""
		if line.isNumber() && line.n > 0 {
			lineText = jsNumber(line.n)
		}
		return displayPath(requireString(uri, "trim")), lineText
	}
	return "(no location)", ""
}

type ruleMap map[string]*value

func rulesByID(run *value) ruleMap {
	rules := ruleMap{}
	tool := get(run, "tool")
	groups := []*value{coalesce(opt(opt(tool, "driver"), "rules"), &value{k: kArr})}
	for _, extension := range iterate(coalesce(opt(tool, "extensions"), &value{k: kArr}), "run.tool.extensions") {
		groups = append(groups, coalesce(get(extension, "rules"), &value{k: kArr}))
	}
	for _, group := range groups {
		for _, rule := range iterate(group, "group") {
			if id := get(rule, "id"); truthy(id) {
				rules[sameValueZeroKey(id)] = rule
			}
		}
	}
	return rules
}

func findingSeverity(result, rule *value) string {
	level := coalesce(coalesce(get(result, "level"), opt(opt(rule, "defaultConfiguration"), "level")), strValue("warning"))
	text := jsLower(requireString(level, "toLowerCase"))
	suppressions := get(result, "suppressions")
	if truthy(suppressions) {
		if n := get(suppressions, "length"); jsGreaterThanZero(n) {
			return text + " (suppressed)"
		}
	}
	return text
}

func jsGreaterThanZero(v *value) bool {
	if v.isString() {
		return stringToNumber(v.s) > 0
	}
	return toNumber(v) > 0
}

func isDiagnosticRule(ruleID *value) bool {
	return reDiagRule.MatchString(asciiLower(toStr(ruleID)))
}

func walk(root string, accept func(string) bool) []string {
	if !exists(root) {
		return nil
	}
	var found []string
	var visit func(current string, depth int)
	visit = func(current string, depth int) {
		if depth > 8 {
			return
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "db-") || skipDirs[name] {
				continue
			}
			full := nodeJoin(current, name)
			if e.IsDir() {
				visit(full, depth+1)
			} else if e.Type().IsRegular() && accept(name) {
				found = append(found, full)
			}
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		throwError("Error", "%s", nodeFsMessage(err, "stat", root))
	}
	if info.Mode().IsRegular() {
		if accept(nodeBasename(root)) {
			found = append(found, root)
		}
		return found
	}
	visit(root, 0)
	return found
}

// findSarifFiles lists SARIF files under root (a file or a directory).
func findSarifFiles(root string) []string {
	return walk(root, func(name string) bool {
		return strings.HasSuffix(name, ".sarif") || strings.HasSuffix(name, ".sarif.json")
	})
}

// checkSarifRoot records why there is nothing to read, if that is the case.
func (t *triage) checkSarifRoot(root string, found int) {
	if !exists(root) {
		t.diagnostics = append(t.diagnostics, diagnostic{"error", tanxSource(), "SARIF path does not exist: " + root})
	} else if found == 0 {
		t.diagnostics = append(t.diagnostics, diagnostic{"error", tanxSource(), "No SARIF files were produced. Analysis stopped before CodeQL wrote results."})
	}
}

// readSarif parses one SARIF file and records its tools, findings,
// diagnostics, and lines-of-code metric.
func (t *triage) readSarif(path string) {
	data, err := os.ReadFile(path)
	var parsed *value
	if err != nil {
		err = errors.New(nodeFsMessage(err, "open", path))
	} else {
		units := decodeUTF8(data)
		if len(units) > 0 && units[0] == 0xFEFF {
			units = units[1:]
		}
		parsed, err = parseJSON(units)
	}
	if err != nil {
		t.unreadableSarif++
		t.diagnostics = append(t.diagnostics, diagnostic{"error", strValue(nodeBasename(path)), "Could not parse SARIF: " + err.Error()})
		return
	}
	for _, run := range iterate(coalesce(get(parsed, "runs"), &value{k: kArr}), "parsed.runs") {
		driver := opt(get(run, "tool"), "driver")
		toolName := or(or(opt(driver, "fullName"), opt(driver, "name")), strValue("CodeQL"))
		if semver := opt(driver, "semanticVersion"); truthy(semver) {
			t.tools = append(t.tools, strValue(toStr(toolName)+" "+toStr(get(driver, "semanticVersion"))))
		} else {
			t.tools = append(t.tools, toolName)
		}
		rules := rulesByID(run)
		for _, invocation := range iterate(coalesce(get(run, "invocations"), &value{k: kArr}), "run.invocations") {
			if ok := get(invocation, "executionSuccessful"); ok != nil && ok.k == kBool && !ok.b {
				exit := ""
				if code := get(invocation, "exitCode"); !code.isUndef() {
					exit = " (exit " + toStr(code) + ")"
				}
				t.diagnostics = append(t.diagnostics, diagnostic{"error", strValue(nodeBasename(path)), "CodeQL invocation failed" + exit + "."})
			}
			notifications := append([]*value{}, iterate(coalesce(get(invocation, "toolExecutionNotifications"), &value{k: kArr}), "toolExecutionNotifications")...)
			notifications = append(notifications, iterate(coalesce(get(invocation, "toolConfigurationNotifications"), &value{k: kArr}), "toolConfigurationNotifications")...)
			var extractedFiles []string
			for _, notification := range notifications {
				source := coalesce(opt(get(notification, "descriptor"), "id"), strValue(nodeBasename(path)))
				uri := opt(opt(opt(opt(get(notification, "locations"), "0"), "physicalLocation"), "artifactLocation"), "uri")
				file := ""
				if truthy(uri) {
					file = displayPath(requireString(uri, "trim"))
				}
				if reExtracted.MatchString(toStr(source)) && file != "" {
					extractedFiles = append(extractedFiles, file)
					continue
				}
				text := messageText(get(notification, "message"))
				attributes := opt(get(notification, "properties"), "attributes")
				attributeText := ""
				if truthy(attributes) {
					var parts []string
					for _, e := range entries(attributes) {
						parts = append(parts, e.key+"="+stringifyShort(e.val))
					}
					attributeText = strings.Join(parts, ", ")
				}
				var kept []string
				for _, part := range []string{text, file, attributeText} {
					if part != "" {
						kept = append(kept, part)
					}
				}
				message := strings.Join(kept, " ")
				severity := jsLower(requireString(coalesce(get(notification, "level"), strValue("warning")), "toLowerCase"))
				if (severity == "none" || severity == "") && message != "" {
					severity = "note"
				}
				if message == "" {
					continue
				}
				t.diagnostics = append(t.diagnostics, diagnostic{severity, source, message})
			}
			if len(extractedFiles) > 0 {
				sort.SliceStable(extractedFiles, func(i, j int) bool { return compareUTF16(extractedFiles[i], extractedFiles[j]) })
				t.diagnostics = append(t.diagnostics, diagnostic{
					"note",
					strValue("diagnostics/successfully-extracted-files"),
					fmt.Sprintf("Extracted %d files: %s", len(extractedFiles), strings.Join(extractedFiles, ", ")),
				})
			}
		}
		metrics := opt(get(run, "properties"), "metricResults")
		if metrics != nil && metrics.k == kArr {
			for _, metric := range metrics.arr {
				if !truthy(metric) || !metric.isObjLike() {
					continue
				}
				ruleID := get(metric, "ruleId")
				v := get(metric, "value")
				if ruleID.isString() && reLinesOfCode.MatchString(ruleID.s) && v.isNumber() {
					n := v.n
					t.linesOfCode = &n
				}
			}
		}
		for _, result := range iterate(coalesce(get(run, "results"), &value{k: kArr}), "run.results") {
			ruleID := or(or(get(result, "ruleId"), opt(get(result, "rule"), "id")), strValue("(no rule)"))
			rule := rules[sameValueZeroKey(ruleID)]
			severity := findingSeverity(result, rule)
			message := messageText(get(result, "message"))
			if message == "" {
				message = messageText(opt(rule, "shortDescription"))
			}
			if message == "" {
				message = "(no message)"
			}
			file, line := locationOf(result)
			if isDiagnosticRule(ruleID) {
				text := file + " " + message
				if line != "" {
					text = file + ":" + line + " " + message
				}
				t.diagnostics = append(t.diagnostics, diagnostic{strings.Replace(severity, " (suppressed)", "", 1), ruleID, text})
			} else {
				t.findings = append(t.findings, finding{severity, ruleID, file, line, message})
			}
		}
	}
}

func stringifyShort(v *value) string {
	switch v.k {
	case kStr:
		return v.s
	case kNum, kBool:
		return toStr(v)
	}
	text := stringify(v)
	if units := toUTF16(text); len(units) > 240 {
		return fromUTF16(units[:237]) + "..."
	}
	return text
}
