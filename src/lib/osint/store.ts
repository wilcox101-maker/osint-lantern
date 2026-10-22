import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import type { Investigation } from "./types";

const file = path.join(process.cwd(), "data", "investigations.json");

let chain: Promise<unknown> = Promise.resolve();

function lock<T>(task: () => Promise<T>): Promise<T> {
  const run = chain.then(task, task);
  chain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

async function readAll(): Promise<Investigation[]> {
  try {
    const raw = await readFile(file, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      throw new Error("The investigation store is not a list.");
    }
    return parsed as Investigation[];
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function writeAll(items: Investigation[]): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(items, null, 2));
  await rename(temporary, file);
}

export function listInvestigations(): Promise<Investigation[]> {
  return lock(async () => {
    const items = await readAll();
    return items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  });
}

export function getInvestigation(id: string): Promise<Investigation | null> {
  return lock(async () => (await readAll()).find((item) => item.id === id) ?? null);
}

export function saveInvestigation(item: Investigation): Promise<Investigation> {
  return lock(async () => {
    const items = await readAll();
    items.push(item);
    await writeAll(items);
    return item;
  });
}

export function deleteInvestigation(id: string): Promise<boolean> {
  return lock(async () => {
    const items = await readAll();
    const next = items.filter((item) => item.id !== id);
    if (next.length === items.length) return false;
    await writeAll(next);
    return true;
  });
}
