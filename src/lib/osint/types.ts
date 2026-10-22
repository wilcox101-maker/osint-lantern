export const SELECTOR_KINDS = [
  "email",
  "domain",
  "ip",
  "username",
  "phone",
] as const;

export type SelectorKind = (typeof SELECTOR_KINDS)[number];

export type Severity = "info" | "low" | "medium" | "high";

export type Confidence = "observed" | "inferred" | "unknown";

export type EvidenceRow = {
  label: string;
  value: string;
};

export type Finding = {
  id: string;
  moduleId: string;
  title: string;
  severity: Severity;
  summary: string;
  remediation?: string;
  evidence: EvidenceRow[];
  source: { name: string; url: string };
  confidence: Confidence;
};

export type ModuleStatus = "ok" | "error" | "skipped";

export type ModuleRun = {
  moduleId: string;
  title: string;
  status: ModuleStatus;
  error?: string;
  durationMs: number;
};

export type Investigation = {
  id: string;
  createdAt: string;
  label: string;
  selector: SelectorKind;
  value: string;
  notes: string;
  passwordChecked: boolean;
  modules: ModuleRun[];
  findings: Finding[];
};

export type ClassifiedSelector =
  | { ok: true; kind: SelectorKind; value: string }
  | { ok: false; error: string };
