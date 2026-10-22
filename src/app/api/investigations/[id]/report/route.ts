import { isInvestigationId } from "@/lib/osint/ids";
import { toMarkdown } from "@/lib/osint/report";
import { getInvestigation } from "@/lib/osint/store";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!isInvestigationId(id)) {
    return new Response("Unknown investigation.", { status: 404 });
  }
  const investigation = await getInvestigation(id);
  if (!investigation) {
    return new Response("Unknown investigation.", { status: 404 });
  }
  return new Response(toMarkdown(investigation), {
    headers: {
      "content-type": "text/markdown; charset=utf-8",
      "content-disposition": `attachment; filename="lantern-${id}.md"`,
    },
  });
}
