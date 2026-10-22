import Link from "next/link";

import { NewInvestigation } from "@/components/new-investigation";
import { SiteFrame } from "@/components/site-frame";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { selectorLabel } from "@/lib/osint/classify";
import { listInvestigations } from "@/lib/osint/store";
import type { Severity } from "@/lib/osint/types";

export const dynamic = "force-dynamic";

const WHEN = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
});

function count(findings: { severity: Severity }[], severity: Severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default async function HomePage() {
  const investigations = await listInvestigations();

  return (
    <SiteFrame>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
        <NewInvestigation />
        <section className="flex flex-col gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Case file</h1>
            <p className="text-sm text-muted-foreground">
              Investigations stay on this machine in <span className="font-mono">data/investigations.json</span>.
            </p>
          </div>
          {investigations.length === 0 ? (
            <Card>
              <CardHeader>
                <CardTitle>No cases yet</CardTitle>
                <CardDescription>
                  A case appears here after a run. example.com is a safe first target: it is reserved for documentation and publishes real DNS.
                </CardDescription>
              </CardHeader>
            </Card>
          ) : (
            investigations.map((investigation) => (
              <Link key={investigation.id} href={`/investigations/${investigation.id}`} className="block">
                <Card className="transition-colors hover:bg-muted/40">
                  <CardHeader>
                    <div className="flex items-start justify-between gap-3">
                      <CardTitle className="font-mono text-sm break-all">{investigation.value}</CardTitle>
                      <Badge variant="secondary">{selectorLabel(investigation.selector)}</Badge>
                    </div>
                    <CardDescription>
                      {WHEN.format(new Date(investigation.createdAt))} UTC · {investigation.findings.length} findings
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <span>{count(investigation.findings, "high")} high</span>
                    <span>{count(investigation.findings, "medium")} medium</span>
                    <span>{count(investigation.findings, "low")} low</span>
                    <span>
                      {investigation.modules.filter((item) => item.status === "error").length} module errors
                    </span>
                  </CardContent>
                </Card>
              </Link>
            ))
          )}
        </section>
      </div>
    </SiteFrame>
  );
}
