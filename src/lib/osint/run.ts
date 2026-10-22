import { randomUUID } from "node:crypto";

import { CATALOG_MODULES, moduleTitle } from "./catalog";
import { classifySelector } from "./classify";
import {
  collectBreachNames,
  collectCertificates,
  collectDns,
  collectGeolocation,
  collectGravatar,
  collectHttpPosture,
  collectMailAuth,
  collectMailbox,
  collectPasswordRange,
  collectPhone,
  collectProfiles,
  collectPublishedFiles,
  collectRegistration,
  collectReverseDns,
} from "./collect";
import { isPrivateAddress } from "./net";
import type { Finding, Investigation, ModuleRun, SelectorKind } from "./types";

type Job = {
  id: string;
  title: string;
  run: () => Promise<Finding[]>;
};

const order = new Map(CATALOG_MODULES.map((item, index) => [item.id, index]));

export async function investigate(input: {
  query: string;
  notes?: string;
  password?: string;
}): Promise<Investigation> {
  const classified = classifySelector(input.query);
  if (!classified.ok) throw new Error(classified.error);
  if (classified.kind === "ip" && isPrivateAddress(classified.value)) {
    throw new Error("Private and reserved addresses are not queried.");
  }
  const password = typeof input.password === "string" ? input.password : "";
  if (password.length > 128) {
    throw new Error("Password checks are limited to 128 characters.");
  }
  const notes = (input.notes ?? "").trim().slice(0, 2000);
  const jobs = jobsFor(classified.kind, classified.value, password);
  const settled = await Promise.all(jobs.map((job) => runJob(job)));
  return {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    label: classified.value,
    selector: classified.kind,
    value: classified.value,
    notes,
    passwordChecked: password.length > 0,
    modules: settled.map((item) => item.module),
    findings: settled.flatMap((item) => item.findings),
  };
}

function jobsFor(kind: SelectorKind, value: string, password: string): Job[] {
  const jobs: Job[] = [];
  const add = (id: string, run: () => Promise<Finding[]>) => {
    jobs.push({ id, title: moduleTitle(id), run });
  };
  const domain = kind === "domain" ? value : kind === "email" ? value.split("@")[1] : null;

  if (kind === "email") add("mailbox", () => collectMailbox(value));
  if (domain) {
    add("dns", () => collectDns(domain));
    add("mail-auth", () => collectMailAuth(domain));
    add("registration", () => collectRegistration(domain, "domain"));
    add("certificates", () => collectCertificates(domain));
    add("http-posture", () => collectHttpPosture(domain));
    add("published-files", () => collectPublishedFiles(domain));
  }
  if (kind === "email") {
    add("gravatar", () => collectGravatar(value));
    add("breach-names", () => collectBreachNames(value));
  }
  if (kind === "username") add("public-profiles", () => collectProfiles(value));
  if (kind === "phone") add("phone-format", () => collectPhone(value));
  if (kind === "ip") {
    add("reverse-dns", () => collectReverseDns(value));
    add("registration", () => collectRegistration(value, "ip"));
    add("geolocation", () => collectGeolocation(value));
  }
  if (password) add("password-range", () => collectPasswordRange(password));
  else {
    add("password-range", async () => {
      throw new Error("SKIP:No password was submitted. The range check runs only when you provide one.");
    });
  }

  jobs.sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0));
  return jobs;
}

async function runJob(job: Job): Promise<{ module: ModuleRun; findings: Finding[] }> {
  const started = Date.now();
  try {
    const findings = await job.run();
    return {
      module: {
        moduleId: job.id,
        title: job.title,
        status: "ok",
        durationMs: Date.now() - started,
      },
      findings,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "The module failed.";
    if (message.startsWith("SKIP:")) {
      return {
        module: {
          moduleId: job.id,
          title: job.title,
          status: "skipped",
          error: message.slice("SKIP:".length),
          durationMs: Date.now() - started,
        },
        findings: [],
      };
    }
    return {
      module: {
        moduleId: job.id,
        title: job.title,
        status: "error",
        error: message,
        durationMs: Date.now() - started,
      },
      findings: [],
    };
  }
}
