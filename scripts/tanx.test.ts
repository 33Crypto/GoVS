import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const script = new URL("./tanx.ts", import.meta.url).pathname;

function run(sarifDir: string) {
  const summary = join(sarifDir, "summary.md");
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", script, "--sarif", sarifDir, "--summary", summary, "--logs", join(sarifDir, "none")],
    { encoding: "utf8", env: { ...process.env, GITHUB_STEP_SUMMARY: "" } },
  );
  return { status: result.status, summary: readFileSync(summary, "utf8") };
}

function sarif(results: unknown[], lines?: number) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "CodeQL", semanticVersion: "2.0.0" } },
        properties: lines === undefined ? {} : { metricResults: [{ ruleId: "go/summary/lines-of-code", value: lines }] },
        results,
      },
    ],
  });
}

test("reports findings, escapes markdown, and exits 0", () => {
  const dir = mkdtempSync(join(tmpdir(), "tanx-"));
  writeFileSync(
    join(dir, "a.sarif"),
    sarif(
      [
        {
          ruleId: "go/sql-injection",
          level: "error",
          message: { text: "bad `code` | <b>x</b>\nsecond line [link](http://x)" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.go" }, region: { startLine: 7 } } }],
        },
      ],
      42,
    ),
  );
  const { status, summary } = run(dir);
  assert.equal(status, 0);
  assert.match(summary, /Analysis status: completed/);
  assert.match(summary, /Findings: 1 \(1 error\)/);
  assert.match(summary, /Lines of code extracted: 42/);
  assert.ok(!summary.includes("<b>"));
  assert.ok(!summary.includes("`code`"));
  assert.match(summary, /src\/a\.go:7/);
});

test("empty SARIF directory is a failure, not a clean result", () => {
  const dir = mkdtempSync(join(tmpdir(), "tanx-"));
  const { status, summary } = run(dir);
  assert.equal(status, 2);
  assert.match(summary, /FAILED/);
  assert.match(summary, /NOT a clean result/);
});

test("unparseable SARIF is a failure", () => {
  const dir = mkdtempSync(join(tmpdir(), "tanx-"));
  writeFileSync(join(dir, "bad.sarif"), "{not json");
  const { status, summary } = run(dir);
  assert.equal(status, 2);
  assert.match(summary, /Could not parse SARIF/);
});
