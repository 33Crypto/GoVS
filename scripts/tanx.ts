/**
 * Summarize CodeQL SARIF for the cosx-vs-tanx-triage pipeline.
 *
 * Reads SARIF results plus extraction and build logs, writes a markdown
 * summary to GITHUB_STEP_SUMMARY, and also writes that summary to disk so
 * the workflow can upload it with the SARIF artifact.
 *
 *   npx --yes tsx@4 scripts/tanx.ts \
 *     --sarif codeql-results \
 *     --summary codeql-results/tanx-summary.md \
 *     --logs "$RUNNER_TEMP/codeql_databases"
 *
 * Node 20+. Uses only node:fs and node:path. Findings do not fail the
 * process; a missing or unreadable SARIF is reported in the summary.
 */

import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

interface Cli {
  sarif: string;
  summary: string;
  logs: string | null;
}

interface SarifMessage {
  text?: string;
  markdown?: string;
}

interface SarifPhysical {
  artifactLocation?: { uri?: string };
  region?: { startLine?: number };
}

interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: SarifMessage;
  locations?: Array<{ physicalLocation?: SarifPhysical }>;
  relatedLocations?: Array<{ physicalLocation?: SarifPhysical }>;
  rule?: { id?: string };
  properties?: Record<string, unknown>;
  suppressions?: unknown[];
}

interface SarifRule {
  id?: string;
  defaultConfiguration?: { level?: string };
  shortDescription?: SarifMessage;
  properties?: Record<string, unknown>;
}

interface SarifNotification {
  message?: SarifMessage;
  level?: string;
  descriptor?: { id?: string };
  locations?: Array<{ physicalLocation?: SarifPhysical }>;
  properties?: { attributes?: Record<string, unknown> };
}

interface SarifRun {
  tool?: {
    driver?: {
      name?: string;
      fullName?: string;
      semanticVersion?: string;
      rules?: SarifRule[];
    };
    extensions?: Array<{ rules?: SarifRule[] }>;
  };
  results?: SarifResult[];
  invocations?: Array<{
    executionSuccessful?: boolean;
    exitCode?: number;
    toolExecutionNotifications?: SarifNotification[];
    toolConfigurationNotifications?: SarifNotification[];
  }>;
  properties?: Record<string, unknown>;
}

interface SarifLog {
  version?: string;
  runs?: SarifRun[];
}

interface Finding {
  severity: string;
  rule: string;
  file: string;
  line: string;
  message: string;
}

interface Diagnostic {
  severity: string;
  source: string;
  message: string;
}

const SEVERITY_RANK: Record<string, number> = {
  error: 0,
  warning: 1,
  note: 2,
  none: 3,
};

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "bin",
  "obj",
  "cache",
  "trap",
]);

function parseArgs(argv: string[]): Cli {
  const cli: Cli = {
    sarif: "codeql-results",
    summary: join("codeql-results", "tanx-summary.md"),
    logs: process.env.RUNNER_TEMP ? join(process.env.RUNNER_TEMP, "codeql_databases") : null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--sarif" && next) {
      cli.sarif = next;
      i += 1;
    } else if (arg === "--summary" && next) {
      cli.summary = next;
      i += 1;
    } else if (arg === "--logs" && next) {
      cli.logs = next;
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write(
        "Usage: tanx.ts --sarif <file-or-dir> --summary <markdown> [--logs <dir>]\n",
      );
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return cli;
}

function messageText(message: SarifMessage | undefined): string {
  const text = message?.text ?? message?.markdown ?? "";
  return text.replace(/\s+/g, " ").trim();
}

function cell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/</g, "&lt;").trim();
}

function severityRank(level: string): number {
  return SEVERITY_RANK[level] ?? 4;
}

function displayPath(uri: string): string {
  let path = uri.trim();
  if (path.startsWith("file://")) {
    path = decodeURIComponent(path.slice("file://".length));
    if (/^\/[A-Za-z]:/.test(path)) {
      path = path.slice(1);
    }
  }
  path = path.replace(/\\/g, "/");
  const workspace = process.env.GITHUB_WORKSPACE;
  if (workspace && path.startsWith("/")) {
    const rel = relative(resolve(workspace), path);
    if (rel !== "" && !rel.startsWith("..") && !rel.startsWith("/")) {
      return rel.replace(/\\/g, "/");
    }
  }
  return path;
}

function locationOf(result: SarifResult): { file: string; line: string } {
  const places = [...(result.locations ?? []), ...(result.relatedLocations ?? [])];
  for (const place of places) {
    const uri = place.physicalLocation?.artifactLocation?.uri;
    if (!uri) {
      continue;
    }
    const line = place.physicalLocation?.region?.startLine;
    return {
      file: displayPath(uri),
      line: typeof line === "number" && line > 0 ? String(line) : "",
    };
  }
  return { file: "(no location)", line: "" };
}

function rulesById(run: SarifRun): Map<string, SarifRule> {
  const map = new Map<string, SarifRule>();
  const groups = [run.tool?.driver?.rules ?? []];
  for (const extension of run.tool?.extensions ?? []) {
    groups.push(extension.rules ?? []);
  }
  for (const group of groups) {
    for (const rule of group) {
      if (rule.id) {
        map.set(rule.id, rule);
      }
    }
  }
  return map;
}

function findingSeverity(result: SarifResult, rule: SarifRule | undefined): string {
  const level = (result.level ?? rule?.defaultConfiguration?.level ?? "warning").toLowerCase();
  if (result.suppressions && result.suppressions.length > 0) {
    return `${level} (suppressed)`;
  }
  return level;
}

function isDiagnosticRule(ruleId: string): boolean {
  return /diagnostic|extractor|successfully-extracted/i.test(ruleId);
}

function walk(root: string, accept: (name: string) => boolean): string[] {
  if (!existsSync(root)) {
    return [];
  }
  const found: string[] = [];
  const visit = (current: string, depth: number): void => {
    if (depth > 8) {
      return;
    }
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith("db-") || SKIP_DIRS.has(entry.name)) {
        continue;
      }
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full, depth + 1);
      } else if (entry.isFile() && accept(entry.name)) {
        found.push(full);
      }
    }
  };
  const stat = statSync(root);
  if (stat.isFile()) {
    if (accept(basename(root))) {
      found.push(root);
    }
    return found;
  }
  visit(root, 0);
  return found;
}

function readCapped(path: string, maxBytes = 1_000_000): string {
  const size = statSync(path).size;
  const data = readFileSync(path);
  const slice = size > maxBytes ? data.subarray(size - maxBytes) : data;
  return slice.toString("utf8");
}

function interestingLogLine(line: string): boolean {
  if (line.length > 500) {
    return false;
  }
  // CodeQL's own query-evaluation log names queries such as "Extraction error"
  // while describing a successful run. Those lines are not build failures.
  if (/Interpreted (diagnostic|problem|pathproblem|metric) query/i.test(line)) {
    return false;
  }
  if (/\[DETAILS\]/i.test(line)) {
    return false;
  }
  return (
    /:\s*(error|warning)\s/i.test(line) ||
    /\b(error|warning)\s+(CS|MSB)\d+/i.test(line) ||
    /\bBuild succeeded\b/i.test(line) ||
    /\bBuild FAILED\b/i.test(line) ||
    /\d+\s+(Error|Warning)\(s\)/.test(line) ||
    /no source code (was )?seen/i.test(line) ||
    /failed to extract/i.test(line) ||
    /\]\s*(ERROR|WARNING)\b/.test(line)
  );
}

function logDiagnostics(path: string): Diagnostic[] {
  const text = readCapped(path);
  const source = basename(path);
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(interestingLogLine);
  const unique: string[] = [];
  for (const line of lines) {
    if (unique[unique.length - 1] !== line) {
      unique.push(line);
    }
  }
  return unique.slice(0, 40).map((line) => {
    let severity = "note";
    if (/error|failed|fatal/i.test(line) && !/0 Error\(s\)/.test(line)) {
      severity = "error";
    } else if (/warning/i.test(line) && !/0 Warning\(s\)/.test(line)) {
      severity = "warning";
    }
    if (/Build succeeded/i.test(line)) {
      severity = "note";
    }
    return { severity, source, message: line };
  });
}

function databaseNotes(root: string): string[] {
  const notes: string[] = [];
  for (const path of walk(root, (name) => name === "codeql-database.yml")) {
    const text = readCapped(path, 100_000);
    const mode = text.match(/^buildMode:\s*(\S+)/m)?.[1];
    const language = text.match(/^primaryLanguage:\s*(\S+)/m)?.[1];
    const parts = [basename(dirname(path))];
    if (language) {
      parts.push(`language=${language}`);
    }
    if (mode) {
      parts.push(`buildMode=${mode}`);
    }
    notes.push(parts.join(" "));
  }
  return notes;
}

function stringifyShort(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    const text = JSON.stringify(value);
    return text.length > 240 ? `${text.slice(0, 237)}...` : text;
  } catch {
    return "";
  }
}

function summarize(cli: Cli): { markdown: string; findingCount: number; diagnosticCount: number } {
  const sarifPaths = walk(cli.sarif, (name) => name.endsWith(".sarif") || name.endsWith(".sarif.json"));
  const logPaths = [
    ...walk(cli.sarif, (name) => name.endsWith(".log")),
    ...(cli.logs ? walk(cli.logs, (name) => name.endsWith(".log") || name.endsWith(".txt")) : []),
  ];
  const findings: Finding[] = [];
  const diagnostics: Diagnostic[] = [];
  const tools: string[] = [];
  let linesOfCode: number | null = null;
  let unreadableSarif = 0;

  if (!existsSync(cli.sarif)) {
    diagnostics.push({
      severity: "error",
      source: "tanx",
      message: `SARIF path does not exist: ${cli.sarif}`,
    });
  } else if (sarifPaths.length === 0) {
    diagnostics.push({
      severity: "error",
      source: "tanx",
      message: "No SARIF files were produced. Analysis stopped before CodeQL wrote results.",
    });
  }

  for (const path of sarifPaths) {
    let parsed: SarifLog;
    try {
      let text = readFileSync(path, "utf8");
      if (text.charCodeAt(0) === 0xfeff) {
        text = text.slice(1);
      }
      parsed = JSON.parse(text) as SarifLog;
    } catch (error) {
      unreadableSarif += 1;
      diagnostics.push({
        severity: "error",
        source: basename(path),
        message: `Could not parse SARIF: ${error instanceof Error ? error.message : String(error)}`,
      });
      continue;
    }
    for (const run of parsed.runs ?? []) {
      const driver = run.tool?.driver;
      const toolName = driver?.fullName || driver?.name || "CodeQL";
      tools.push(driver?.semanticVersion ? `${toolName} ${driver.semanticVersion}` : toolName);
      const rules = rulesById(run);
      for (const invocation of run.invocations ?? []) {
        if (invocation.executionSuccessful === false) {
          diagnostics.push({
            severity: "error",
            source: basename(path),
            message: `CodeQL invocation failed${invocation.exitCode !== undefined ? ` (exit ${invocation.exitCode})` : ""}.`,
          });
        }
        const notifications = [
          ...(invocation.toolExecutionNotifications ?? []),
          ...(invocation.toolConfigurationNotifications ?? []),
        ];
        const extractedFiles: string[] = [];
        for (const notification of notifications) {
          const source = notification.descriptor?.id ?? basename(path);
          const uri = notification.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
          const file = uri ? displayPath(uri) : "";
          if (source === "cs/diagnostics/successfully-extracted-files" && file) {
            extractedFiles.push(file);
            continue;
          }
          const text = messageText(notification.message);
          const attributes = notification.properties?.attributes;
          const attributeText = attributes
            ? Object.entries(attributes)
                .map(([key, value]) => `${key}=${stringifyShort(value)}`)
                .join(", ")
            : "";
          const message = [text, file, attributeText].filter((part) => part !== "").join(" ");
          let severity = (notification.level ?? "warning").toLowerCase();
          if ((severity === "none" || severity === "") && message !== "") {
            severity = "note";
          }
          if (message === "") {
            continue;
          }
          diagnostics.push({ severity, source, message });
        }
        if (extractedFiles.length > 0) {
          extractedFiles.sort();
          diagnostics.push({
            severity: "note",
            source: "cs/diagnostics/successfully-extracted-files",
            message: `Extracted ${extractedFiles.length} files: ${extractedFiles.join(", ")}`,
          });
        }
      }
      const metrics = run.properties?.metricResults;
      if (Array.isArray(metrics)) {
        for (const metric of metrics) {
          if (!metric || typeof metric !== "object") {
            continue;
          }
          const record = metric as { ruleId?: string; value?: unknown };
          if (record.ruleId === "cs/summary/lines-of-code" && typeof record.value === "number") {
            linesOfCode = record.value;
          }
        }
      }
      for (const result of run.results ?? []) {
        const ruleId = result.ruleId || result.rule?.id || "(no rule)";
        const rule = rules.get(ruleId);
        const severity = findingSeverity(result, rule);
        const message = messageText(result.message) || messageText(rule?.shortDescription) || "(no message)";
        const location = locationOf(result);
        const item: Finding = {
          severity,
          rule: ruleId,
          file: location.file,
          line: location.line,
          message,
        };
        if (isDiagnosticRule(ruleId)) {
          diagnostics.push({
            severity: severity.replace(" (suppressed)", ""),
            source: ruleId,
            message: location.line ? `${location.file}:${location.line} ${message}` : `${location.file} ${message}`,
          });
        } else {
          findings.push(item);
        }
      }
    }
  }

  for (const path of logPaths) {
    diagnostics.push(...logDiagnostics(path));
  }

  const dbNotes = cli.logs && existsSync(cli.logs) ? databaseNotes(cli.logs) : [];
  if (cli.logs && !existsSync(cli.logs)) {
    diagnostics.push({
      severity: "note",
      source: "tanx",
      message: `CodeQL database log directory was not found: ${cli.logs}`,
    });
  }

  findings.sort((a, b) => {
    const rank = severityRank(a.severity) - severityRank(b.severity);
    if (rank !== 0) {
      return rank;
    }
    const file = a.file.localeCompare(b.file);
    if (file !== 0) {
      return file;
    }
    return Number(a.line || 0) - Number(b.line || 0);
  });

  const counts = new Map<string, number>();
  for (const finding of findings) {
    const key = finding.severity.replace(" (suppressed)", "");
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const countText = [...counts.entries()].map(([level, count]) => `${count} ${level}`).join(", ");

  const lines: string[] = [];
  lines.push("## cosx-vs-tanx-triage");
  lines.push("");
  lines.push("### Analysis");
  lines.push("");
  lines.push(`- SARIF files: ${sarifPaths.length}`);
  if (tools.length > 0) {
    lines.push(`- Tool: ${[...new Set(tools)].join(", ")}`);
  }
  lines.push(`- Findings: ${findings.length}${countText ? ` (${countText})` : ""}`);
  if (linesOfCode !== null) {
    lines.push(`- C# lines extracted: ${linesOfCode}`);
  }
  if (dbNotes.length > 0) {
    lines.push(`- Database: ${dbNotes.join("; ")}`);
  }
  lines.push("");
  lines.push("### Findings");
  lines.push("");
  if (findings.length === 0 && unreadableSarif > 0) {
    lines.push("No findings could be read. One or more SARIF files failed to parse; see extraction and build.");
  } else if (findings.length === 0) {
    lines.push("CodeQL reported no findings.");
  } else {
    lines.push("| Severity | Rule | Location | Message |");
    lines.push("| --- | --- | --- | --- |");
    for (const finding of findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      lines.push(
        `| ${cell(finding.severity)} | ${cell(finding.rule)} | ${cell(location)} | ${cell(finding.message)} |`,
      );
    }
  }
  lines.push("");
  lines.push("### Extraction and build");
  lines.push("");
  if (diagnostics.length === 0) {
    lines.push("No extraction or build errors or warnings were recorded.");
  } else {
    const shown = diagnostics.slice(0, 60);
    lines.push("| Severity | Source | Message |");
    lines.push("| --- | --- | --- |");
    for (const diagnostic of shown) {
      lines.push(
        `| ${cell(diagnostic.severity)} | ${cell(diagnostic.source)} | ${cell(diagnostic.message)} |`,
      );
    }
    if (diagnostics.length > shown.length) {
      lines.push("");
      lines.push(`Showing ${shown.length} of ${diagnostics.length} diagnostic lines.`);
    }
  }
  lines.push("");

  return {
    markdown: `${lines.join("\n")}\n`,
    findingCount: findings.length,
    diagnosticCount: diagnostics.length,
  };
}

function main(): void {
  const cli = parseArgs(process.argv.slice(2));
  const { markdown, findingCount, diagnosticCount } = summarize(cli);
  mkdirSync(dirname(resolve(cli.summary)), { recursive: true });
  writeFileSync(cli.summary, markdown);
  const stepSummary = process.env.GITHUB_STEP_SUMMARY;
  if (stepSummary) {
    appendFileSync(stepSummary, markdown);
  }
  process.stdout.write(markdown);
  process.stdout.write(`tanx: ${findingCount} finding(s), ${diagnosticCount} diagnostic line(s)\n`);
}

main();
