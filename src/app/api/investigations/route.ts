import { NextResponse } from "next/server";

import { investigate } from "@/lib/osint/run";
import { listInvestigations, saveInvestigation } from "@/lib/osint/store";

export const dynamic = "force-dynamic";

const hits: number[] = [];

export async function GET() {
  const items = await listInvestigations();
  return NextResponse.json(items);
}

export async function POST(request: Request) {
  const now = Date.now();
  while (hits.length > 0 && now - hits[0] > 60_000) hits.shift();
  if (hits.length >= 8) {
    return NextResponse.json(
      { error: "Lantern is pausing after eight investigations in a minute." },
      { status: 429 },
    );
  }

  let body: { query?: unknown; notes?: unknown; password?: unknown };
  try {
    body = (await request.json()) as { query?: unknown; notes?: unknown; password?: unknown };
  } catch {
    return NextResponse.json({ error: "Send a JSON body." }, { status: 400 });
  }
  if (typeof body.query !== "string" || !body.query.trim()) {
    return NextResponse.json({ error: "Enter a target." }, { status: 400 });
  }

  hits.push(now);
  try {
    const investigation = await investigate({
      query: body.query,
      notes: typeof body.notes === "string" ? body.notes : "",
      password: typeof body.password === "string" ? body.password : "",
    });
    await saveInvestigation(investigation);
    return NextResponse.json(investigation);
  } catch (error) {
    hits.pop();
    const message = error instanceof Error ? error.message : "The investigation failed.";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
