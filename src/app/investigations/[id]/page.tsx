import Link from "next/link";
import { notFound } from "next/navigation";

import { DeleteInvestigation } from "@/components/delete-investigation";
import { SiteFrame } from "@/components/site-frame";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { selectorLabel } from "@/lib/osint/classify";
import { isInvestigationId } from "@/lib/osint/ids";
import { getInvestigation } from "@/lib/osint/store";
import type { Finding, ModuleRun, Severity } from "@/lib/osint/types";

export const dynamic = "force-dynamic";

const WHEN = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
});

const SEVERITIES: Severity[] = ["high", "medium", "low", "info"];

function severityVariant(severity: Severity): "destructive" | "outline" | "secondary" {
  if (severity === "high") return "destructive";
  if (severity === "medium") return "outline";
  return "secondary";
}

function statusVariant(status: ModuleRun["status"]): "destructive" | "outline" | "secondary" {
  if (status === "error") return "destructive";
  if (status === "skipped") return "outline";
  return "secondary";
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
          <Badge variant="outline">{finding.confidence}</Badge>
        </div>
        <CardTitle>{finding.title}</CardTitle>
        <CardDescription>{finding.summary}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {finding.remediation ? (
          <p className="text-sm">
            <span className="font-medium">Fix. </span>
            {finding.remediation}
          </p>
        ) : null}
        {finding.evidence.length > 0 ? (
          <dl className="grid gap-2">
            {finding.evidence.map((row, index) => (
              <div key={`${row.label}-${index}`} className="grid gap-1 sm:grid-cols-[8rem_minmax(0,1fr)]">
                <dt className="text-xs tracking-wide text-muted-foreground uppercase">{row.label}</dt>
                <dd className="font-mono text-xs break-all">{row.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        <Separator />
        <p className="text-xs text-muted-foreground">
          Source:{" "}
          {finding.source.url ? (
            <a className="text-foreground underline-offset-4 hover:underline" href={finding.source.url}>
              {finding.source.name}
            </a>
          ) : (
            finding.source.name
          )}
        </p>
      </CardContent>
    </Card>
  );
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return { title: isInvestigationId(id) ? "Investigation" : "Missing investigation" };
}

export default async function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!isInvestigationId(id)) notFound();
  const investigation = await getInvestigation(id);
  if (!investigation) notFound();

  const errors = investigation.modules.filter((item) => item.status === "error");

  return (
    <SiteFrame>
      <div className="flex flex-col gap-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs tracking-wide text-muted-foreground uppercase">
              {selectorLabel(investigation.selector)} · {WHEN.format(new Date(investigation.createdAt))} UTC
            </p>
            <h1 className="mt-1 font-mono text-2xl font-semibold break-all">{investigation.value}</h1>
            {investigation.notes ? (
              <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{investigation.notes}</p>
            ) : null}
            <p className="mt-2 text-xs text-muted-foreground">
              {investigation.passwordChecked
                ? "A password was submitted for the range check and was not stored."
                : "No password was submitted."}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link
              href={`/investigations/${investigation.id}/report`}
              className="inline-flex h-8 items-center rounded-lg border border-border px-2.5 text-sm hover:bg-muted"
            >
              Read report
            </Link>
            <a
              href={`/api/investigations/${investigation.id}/report`}
              className="inline-flex h-8 items-center rounded-lg bg-primary px-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/80"
            >
              Download Markdown
            </a>
            <DeleteInvestigation id={investigation.id} />
          </div>
        </div>

        {investigation.findings.length === 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>No findings</CardTitle>
              <CardDescription>
                {errors.length > 0
                  ? "Every module that should have produced evidence failed. The module list below has the reason."
                  : "The modules finished without a finding to record."}
              </CardDescription>
            </CardHeader>
          </Card>
        ) : (
          SEVERITIES.map((severity) => {
            const group = investigation.findings.filter((finding) => finding.severity === severity);
            if (group.length === 0) return null;
            return (
              <section key={severity} className="flex flex-col gap-3">
                <h2 className="text-sm font-medium tracking-wide text-muted-foreground uppercase">
                  {severity} · {group.length}
                </h2>
                <div className="grid gap-3">
                  {group.map((finding) => (
                    <FindingCard key={finding.id} finding={finding} />
                  ))}
                </div>
              </section>
            );
          })
        )}

        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-medium tracking-wide text-muted-foreground uppercase">Modules</h2>
          <div className="grid gap-2">
            {investigation.modules.map((moduleRun) => (
              <div
                key={moduleRun.moduleId}
                className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-card px-4 py-3 ring-1 ring-foreground/10"
              >
                <div>
                  <p className="text-sm font-medium">{moduleRun.title}</p>
                  {moduleRun.error ? <p className="text-xs text-muted-foreground">{moduleRun.error}</p> : null}
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">{moduleRun.durationMs} ms</span>
                  <Badge variant={statusVariant(moduleRun.status)}>{moduleRun.status}</Badge>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </SiteFrame>
  );
}
