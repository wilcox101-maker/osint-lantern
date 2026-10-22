import { NextResponse } from "next/server";

import { isInvestigationId } from "@/lib/osint/ids";
import { deleteInvestigation, getInvestigation } from "@/lib/osint/store";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export async function GET(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!isInvestigationId(id)) {
    return NextResponse.json({ error: "Unknown investigation." }, { status: 404 });
  }
  const investigation = await getInvestigation(id);
  if (!investigation) {
    return NextResponse.json({ error: "Unknown investigation." }, { status: 404 });
  }
  return NextResponse.json(investigation);
}

export async function DELETE(_request: Request, context: Context) {
  const { id } = await context.params;
  if (!isInvestigationId(id)) {
    return NextResponse.json({ error: "Unknown investigation." }, { status: 404 });
  }
  const removed = await deleteInvestigation(id);
  if (!removed) {
    return NextResponse.json({ error: "Unknown investigation." }, { status: 404 });
  }
  return NextResponse.json({ ok: true });
}
