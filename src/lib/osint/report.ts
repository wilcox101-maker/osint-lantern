import type { Investigation } from "./types";

export function toMarkdown(investigation: Investigation): string {
  const lines = [
    "# Lantern investigation",
    "",
    `- Selector: ${investigation.selector}`,
    `- Value: ${investigation.value}`,
    `- Opened: ${investigation.createdAt}`,
    `- Password submitted for a range check: ${investigation.passwordChecked ? "yes, the value was not stored" : "no"}`,
    "",
  ];
  if (investigation.notes) {
    lines.push("## Notes", "", investigation.notes, "");
  }
  lines.push("## Modules", "");
  for (const moduleRun of investigation.modules) {
    const detail = moduleRun.error ? ` — ${moduleRun.error}` : "";
    lines.push(`- ${moduleRun.title}: ${moduleRun.status}${detail} (${moduleRun.durationMs} ms)`);
  }
  lines.push("", "## Findings", "");
  if (investigation.findings.length === 0) {
    lines.push("No findings were recorded.");
    lines.push("");
  }
  for (const finding of investigation.findings) {
    lines.push(`### ${finding.title}`, "", finding.summary, "");
    if (finding.remediation) lines.push(`Remediation: ${finding.remediation}`, "");
    for (const row of finding.evidence) {
      lines.push(`- ${row.label}: ${row.value}`);
    }
    if (finding.evidence.length > 0) lines.push("");
    const source = finding.source.url
      ? `${finding.source.name} (${finding.source.url})`
      : finding.source.name;
    lines.push(`Source: ${source}`, `Confidence: ${finding.confidence}`, `Severity: ${finding.severity}`, "");
  }
  lines.push("Lantern did not store a password, national ID, or exploit payload for this case.");
  lines.push("");
  return lines.join("\n");
}
