import Link from "next/link";
import { notFound } from "next/navigation";

import { SiteFrame } from "@/components/site-frame";
import { isInvestigationId } from "@/lib/osint/ids";
import { toMarkdown } from "@/lib/osint/report";
import { getInvestigation } from "@/lib/osint/store";

export const dynamic = "force-dynamic";

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!isInvestigationId(id)) notFound();
  const investigation = await getInvestigation(id);
  if (!investigation) notFound();
  const markdown = toMarkdown(investigation);

  return (
    <SiteFrame>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Source-linked report</h1>
          <p className="text-sm text-muted-foreground">Plain Markdown. Nothing here is rendered as HTML.</p>
        </div>
        <div className="flex gap-3 text-sm">
          <Link href={`/investigations/${id}`} className="underline-offset-4 hover:underline">
            Back to findings
          </Link>
          <a href={`/api/investigations/${id}/report`} className="underline-offset-4 hover:underline">
            Download
          </a>
        </div>
      </div>
      <pre className="overflow-x-auto rounded-xl bg-card p-4 font-mono text-xs leading-5 ring-1 ring-foreground/10 whitespace-pre-wrap">
        {markdown}
      </pre>
    </SiteFrame>
  );
}
