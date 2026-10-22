import { createHash } from "node:crypto";
import { resolve4, resolve6, resolveMx, resolveNs, resolveTxt, reverse } from "node:dns/promises";
import { parsePhoneNumberFromString } from "libphonenumber-js";

import { isRoleMailbox } from "./classify";
import { assertPublicHostname, fetchPublic, isPrivateAddress } from "./net";
import { gradeDmarc, gradeHeaders, gradeSpf, passwordRangeSummary } from "./posture";
import type { Confidence, EvidenceRow, Finding, Severity } from "./types";

export type Draft = {
  title: string;
  severity: Severity;
  summary: string;
  remediation?: string;
  evidence?: EvidenceRow[];
  source: { name: string; url: string };
  confidence?: Confidence;
};

export function stamp(moduleId: string, drafts: Draft[]): Finding[] {
  return drafts.map((draft, index) => ({
    id: `${moduleId}-${index + 1}`,
    moduleId,
    title: draft.title,
    severity: draft.severity,
    summary: draft.summary,
    remediation: draft.remediation,
    evidence: draft.evidence ?? [],
    source: draft.source,
    confidence: draft.confidence ?? "observed",
  }));
}

async function records(kind: string, lookup: () => Promise<string[]>): Promise<string[]> {
  try {
    return await lookup();
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENODATA" || code === "ENOTFOUND" || code === "ESERVFAIL") return [];
    throw new Error(`${kind} lookup failed${code ? ` (${code})` : ""}.`);
  }
}

function clip(value: string, max = 240): string {
  const clean = value.replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export async function collectMailbox(email: string): Promise<Finding[]> {
  const role = isRoleMailbox(email);
  return stamp("mailbox", [
    {
      title: role ? "Shared mailbox name" : "Personal-looking mailbox name",
      severity: role ? "low" : "info",
      summary: role
        ? "The local part is a shared role name. Exposure here often belongs to a team, not one person."
        : "The local part is not one of the usual shared role names.",
      evidence: [{ label: "Address", value: email }],
      source: { name: "Lantern mailbox list", url: "" },
      confidence: "inferred",
    },
  ]);
}

export async function collectDns(domain: string): Promise<Finding[]> {
  await assertPublicHostname(domain);
  const [a, aaaa, mx, ns, txt] = await Promise.all([
    records("A", async () => resolve4(domain)),
    records("AAAA", async () => resolve6(domain)),
    records("MX", async () =>
      (await resolveMx(domain)).map((item) =>
        item.exchange ? `${item.priority} ${item.exchange}` : `${item.priority} (empty exchange)`,
      ),
    ),
    records("NS", async () => resolveNs(domain)),
    records("TXT", async () => (await resolveTxt(domain)).map((parts) => parts.join(""))),
  ]);
  const evidence: EvidenceRow[] = [
    { label: "A", value: a.slice(0, 12).join(", ") || "none" },
    { label: "AAAA", value: aaaa.slice(0, 12).join(", ") || "none" },
    { label: "MX", value: mx.slice(0, 12).join(", ") || "none" },
    { label: "NS", value: ns.slice(0, 12).join(", ") || "none" },
    ...txt.slice(0, 8).map((record, index) => ({ label: `TXT ${index + 1}`, value: clip(record) })),
  ];
  const empty = a.length + aaaa.length + mx.length + ns.length + txt.length === 0;
  return stamp("dns", [
    {
      title: empty ? "No public DNS records" : "Public DNS records",
      severity: empty ? "medium" : "info",
      summary: empty
        ? `${domain} did not return A, AAAA, MX, NS, or TXT records.`
        : `${domain} publishes ${a.length} A, ${aaaa.length} AAAA, ${mx.length} MX, ${ns.length} NS, and ${txt.length} TXT records.`,
      evidence,
      source: { name: "Recursive DNS", url: "" },
    },
  ]);
}

export async function collectMailAuth(domain: string): Promise<Finding[]> {
  await assertPublicHostname(domain);
  const txt = await records("TXT", async () => (await resolveTxt(domain)).map((parts) => parts.join("")));
  let dmarc: string | null = null;
  try {
    const rows = await resolveTxt(`_dmarc.${domain}`);
    dmarc = rows.map((parts) => parts.join("")).find((row) => /v\s*=\s*DMARC1/i.test(row)) ?? null;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code !== "ENODATA" && code !== "ENOTFOUND" && code !== "ESERVFAIL") {
      throw new Error(`DMARC lookup failed${code ? ` (${code})` : ""}.`);
    }
  }
  const spf = gradeSpf(txt);
  const dmarcGrade = gradeDmarc(dmarc);
  return stamp("mail-auth", [
    {
      ...spf,
      evidence: txt.filter((row) => row.toLowerCase().startsWith("v=spf1")).map((row) => ({
        label: "SPF",
        value: clip(row),
      })),
      source: { name: "DNS TXT", url: "" },
    },
    {
      ...dmarcGrade,
      evidence: dmarc ? [{ label: "DMARC", value: clip(dmarc) }] : [],
      source: { name: "DNS TXT at _dmarc", url: "" },
    },
    {
      title: "DKIM selectors were not guessed",
      severity: "info",
      summary: "Lantern does not try selector names. A missing result here is not proof that DKIM is absent.",
      source: { name: "Lantern", url: "" },
      confidence: "inferred",
    },
  ]);
}

type RdapDocument = {
  ldhName?: string;
  handle?: string;
  name?: string;
  status?: string[];
  startAddress?: string;
  endAddress?: string;
  port43?: string;
  nameservers?: { ldhName?: string }[];
  events?: { eventAction?: string; eventDate?: string }[];
};

export async function collectRegistration(target: string, kind: "domain" | "ip"): Promise<Finding[]> {
  if (kind === "ip" && isPrivateAddress(target)) {
    throw new Error("Private and reserved addresses are not queried.");
  }
  if (kind === "domain") await assertPublicHostname(target);
  const url = `https://rdap.org/${kind}/${encodeURIComponent(target)}`;
  const response = await fetchPublic(url, { maxBytes: 80_000, timeoutMs: 10_000, headers: { accept: "application/rdap+json, application/json" } });
  if (response.status === 404) {
    return stamp("registration", [
      {
        title: "No public registration record",
        severity: "info",
        summary: `RDAP returned 404 for ${target}.`,
        source: { name: "RDAP", url },
      },
    ]);
  }
  if (response.status >= 400) {
    throw new Error(`RDAP returned HTTP ${response.status}.`);
  }
  const document = JSON.parse(response.body) as RdapDocument;
  const events = (document.events ?? [])
    .filter((event) => event.eventAction && event.eventDate)
    .slice(0, 6)
    .map((event) => ({
      label: event.eventAction ?? "event",
      value: event.eventDate ?? "",
    }));
  const nameservers = (document.nameservers ?? [])
    .map((server) => server.ldhName)
    .filter((name): name is string => Boolean(name))
    .slice(0, 8);
  return stamp("registration", [
    {
      title: "Public registration record",
      severity: "info",
      summary: document.ldhName || document.name || document.handle || target,
      evidence: [
        document.handle ? { label: "Handle", value: document.handle } : undefined,
        document.status?.length ? { label: "Status", value: document.status.slice(0, 8).join(", ") } : undefined,
        document.startAddress ? { label: "Start", value: document.startAddress } : undefined,
        document.endAddress ? { label: "End", value: document.endAddress } : undefined,
        nameservers.length ? { label: "Nameservers", value: nameservers.join(", ") } : undefined,
        ...events,
      ].filter((row): row is EvidenceRow => Boolean(row)),
      source: { name: "RDAP", url },
    },
  ]);
}

type SpotterIssuance = { dns_names?: string[] };
type CrtRow = { name_value?: string };

function rememberName(names: Set<string>, domain: string, raw: string) {
  const name = raw.trim().toLowerCase().replace(/^\*\./, "");
  if (!name || name.includes(" ")) return;
  if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
}

export async function collectCertificates(domain: string): Promise<Finding[]> {
  await assertPublicHostname(domain);
  const names = new Set<string>();
  let source = { name: "Cert Spotter", url: "" };
  const spotter = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
  const crt = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  let spotterError = "";

  try {
    const response = await fetchPublic(spotter, {
      maxBytes: 240_000,
      timeoutMs: 12_000,
      headers: { accept: "application/json" },
    });
    if (response.status >= 400) throw new Error(`Cert Spotter returned HTTP ${response.status}.`);
    const issuances = JSON.parse(response.body) as SpotterIssuance[];
    for (const issuance of issuances) {
      for (const dnsName of issuance.dns_names ?? []) rememberName(names, domain, dnsName);
    }
    source = { name: "Cert Spotter", url: spotter };
  } catch (error) {
    spotterError = error instanceof Error ? error.message : "Cert Spotter failed.";
    const response = await fetchPublic(crt, {
      maxBytes: 240_000,
      timeoutMs: 12_000,
      headers: { accept: "application/json" },
    });
    if (response.status >= 400 || response.body.trim().startsWith("<")) {
      throw new Error(`${spotterError} crt.sh returned HTTP ${response.status}.`);
    }
    const rows = JSON.parse(response.body) as CrtRow[];
    for (const row of rows) {
      for (const part of (row.name_value ?? "").split("\n")) rememberName(names, domain, part);
    }
    source = { name: "crt.sh", url: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}` };
  }

  const list = [...names].sort().slice(0, 40);
  return stamp("certificates", [
    {
      title: list.length ? "Names in certificate logs" : "No certificate names returned",
      severity: "info",
      summary: list.length
        ? `${names.size} distinct names were published for ${domain}. ${names.size > list.length ? `Showing ${list.length}.` : ""}`.trim()
        : `The certificate log returned no names for ${domain}.`,
      evidence: list.map((name) => ({ label: "Name", value: name })),
      source,
    },
  ]);
}

export async function collectHttpPosture(domain: string): Promise<Finding[]> {
  await assertPublicHostname(domain);
  const url = `https://${domain}/`;
  const response = await fetchPublic(url, { maxBytes: 4_000, timeoutMs: 8_000 });
  const grades = gradeHeaders(response.headers);
  return stamp(
    "http-posture",
    grades.map((grade) => ({
      ...grade,
      evidence: [{ label: "Final URL", value: response.finalUrl }, { label: "Status", value: String(response.status) }],
      source: { name: "HTTPS response headers", url: response.finalUrl },
    })),
  );
}

export async function collectPublishedFiles(domain: string): Promise<Finding[]> {
  await assertPublicHostname(domain);
  const paths = [
    { path: "/robots.txt", label: "robots.txt" },
    { path: "/.well-known/security.txt", label: "security.txt" },
  ];
  const drafts: Draft[] = [];
  for (const item of paths) {
    const url = `https://${domain}${item.path}`;
    try {
      const response = await fetchPublic(url, { maxBytes: 8_000, timeoutMs: 8_000 });
      const present = response.status >= 200 && response.status < 300 && response.body.trim().length > 0;
      drafts.push({
        title: present ? `${item.label} is published` : `${item.label} was not published`,
        severity: present || item.label === "robots.txt" ? "info" : "low",
        summary: present
          ? `HTTP ${response.status}, ${response.body.trim().length} characters.`
          : `HTTP ${response.status}.`,
        remediation:
          item.label === "security.txt" && !present
            ? "Publish a security.txt file with a contact for vulnerability reports."
            : undefined,
        evidence: present ? [{ label: "Excerpt", value: clip(response.body, 320) }] : [],
        source: { name: item.label, url: response.finalUrl },
      });
    } catch (error) {
      drafts.push({
        title: `${item.label} could not be fetched`,
        severity: "info",
        summary: error instanceof Error ? error.message : "The request failed.",
        source: { name: item.label, url },
        confidence: "unknown",
      });
    }
  }
  return stamp("published-files", drafts);
}

export async function collectGravatar(email: string): Promise<Finding[]> {
  const hash = createHash("md5").update(email.trim().toLowerCase()).digest("hex");
  const url = `https://www.gravatar.com/avatar/${hash}?d=404`;
  let response;
  try {
    response = await fetchPublic(url, { method: "HEAD", maxBytes: 1, timeoutMs: 8_000 });
    if (response.status === 405 || response.status === 400) {
      response = await fetchPublic(url, { method: "GET", maxBytes: 65_536, timeoutMs: 8_000 });
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("larger than Lantern")) {
      return stamp("gravatar", [
        {
          title: "Public Gravatar exists",
          severity: "info",
          summary: "A default-free Gravatar request returned an image for this address.",
          evidence: [{ label: "Avatar", value: `https://www.gravatar.com/avatar/${hash}` }],
          source: { name: "Gravatar", url },
        },
      ]);
    }
    throw error;
  }
  const present = response.status === 200;
  return stamp("gravatar", [
    {
      title: present ? "Public Gravatar exists" : "No public Gravatar",
      severity: "info",
      summary: present
        ? "A default-free Gravatar request returned an image for this address."
        : `Gravatar returned HTTP ${response.status}.`,
      evidence: present ? [{ label: "Avatar", value: `https://www.gravatar.com/avatar/${hash}` }] : [],
      source: { name: "Gravatar", url },
    },
  ]);
}

type ProfileVerdict = "present" | "absent" | "inconclusive";

const PROFILE_SITES: {
  name: string;
  url: (username: string) => string;
  judge: (status: number, body: string, truncated: boolean) => ProfileVerdict;
}[] = [
  {
    name: "GitHub",
    url: (username) => `https://github.com/${encodeURIComponent(username)}`,
    judge: (status) => (status === 404 ? "absent" : status === 200 ? "present" : "inconclusive"),
  },
  {
    name: "GitLab",
    url: (username) => `https://gitlab.com/${encodeURIComponent(username)}`,
    judge: (status) => (status === 404 ? "absent" : status === 200 ? "present" : "inconclusive"),
  },
  {
    name: "YouTube",
    url: (username) => `https://www.youtube.com/@${encodeURIComponent(username)}`,
    judge: (status) => (status === 404 ? "absent" : status === 200 ? "present" : "inconclusive"),
  },
  {
    name: "Reddit",
    url: (username) => `https://www.reddit.com/user/${encodeURIComponent(username)}`,
    judge: (status, body) => {
      if (status === 404) return "absent";
      if (status === 200 && /sorry, nobody on reddit|page not found/i.test(body)) return "absent";
      if (status === 200) return "present";
      return "inconclusive";
    },
  },
  {
    name: "npm",
    url: (username) => `https://www.npmjs.com/~${encodeURIComponent(username)}`,
    judge: (status) => (status === 404 ? "absent" : status === 200 ? "present" : "inconclusive"),
  },
  {
    name: "Telegram",
    url: (username) => `https://t.me/${encodeURIComponent(username)}`,
    judge: (status, body, truncated) => {
      if (status !== 200) return "inconclusive";
      if (body.includes("tgme_page_extra")) return "present";
      return truncated ? "inconclusive" : "absent";
    },
  },
  {
    name: "Bluesky",
    url: (username) =>
      `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(username)}.bsky.social`,
    judge: (status, body) => {
      if (status === 200 && body.includes('"did"')) return "present";
      if (status === 400) return "absent";
      return "inconclusive";
    },
  },
];

const PROFILE_COPY: Record<ProfileVerdict, { title: string; summary: string; confidence: Confidence }> = {
  present: {
    title: "page exists",
    summary: "A public page or record answered. That is a candidate, not proof this person controls it.",
    confidence: "inferred",
  },
  absent: {
    title: "not listed",
    summary: "This source has no public record at that name.",
    confidence: "observed",
  },
  inconclusive: {
    title: "inconclusive",
    summary: "The source did not give a clear yes or no.",
    confidence: "unknown",
  },
};

export async function collectProfiles(username: string): Promise<Finding[]> {
  const drafts = await mapPool(PROFILE_SITES, 4, async (site) => {
    const url = site.url(username);
    try {
      const response = await fetchPublic(url, {
        maxBytes: 24_000,
        timeoutMs: 7_000,
        onOverflow: "truncate",
      });
      const verdict = site.judge(response.status, response.body, response.truncated);
      const copy = PROFILE_COPY[verdict];
      return {
        title: `${site.name}: ${copy.title}`,
        severity: "info" as const,
        summary: verdict === "inconclusive" ? `${copy.summary} HTTP ${response.status}.` : copy.summary,
        evidence: [{ label: "HTTP", value: String(response.status) }],
        source: { name: site.name, url: response.finalUrl },
        confidence: copy.confidence,
      };
    } catch (error) {
      return {
        title: `${site.name}: no answer`,
        severity: "info" as const,
        summary: error instanceof Error ? error.message : "The request failed.",
        source: { name: site.name, url },
        confidence: "unknown" as const,
      };
    }
  });
  return stamp("public-profiles", drafts);
}

async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

type HibpBreach = {
  Title?: string;
  Name?: string;
  BreachDate?: string;
  DataClasses?: string[];
  IsVerified?: boolean;
};

export async function collectBreachNames(email: string): Promise<Finding[]> {
  const key = process.env.HIBP_API_KEY?.trim();
  if (!key) {
    throw new Error("SKIP:HIBP_API_KEY is not set, so breach titles are not requested.");
  }
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  const response = await fetchPublic(url, {
    maxBytes: 200_000,
    timeoutMs: 10_000,
    headers: {
      "hibp-api-key": key,
      "user-agent": "LanternOSINT",
      accept: "application/json",
    },
  });
  if (response.status === 404) {
    return stamp("breach-names", [
      {
        title: "No breach titles for this address",
        severity: "info",
        summary: "Have I Been Pwned returned 404, which means no breach name is on file for this account.",
        source: { name: "Have I Been Pwned", url: "https://haveibeenpwned.com/" },
      },
    ]);
  }
  if (response.status >= 400) {
    throw new Error(`Have I Been Pwned returned HTTP ${response.status}.`);
  }
  const breaches = JSON.parse(response.body) as HibpBreach[];
  const shown = breaches.slice(0, 30);
  return stamp("breach-names", [
    {
      title: `${breaches.length} breach ${breaches.length === 1 ? "title" : "titles"}`,
      severity: breaches.length > 0 ? "medium" : "info",
      summary:
        breaches.length > shown.length
          ? `Showing ${shown.length} of ${breaches.length} titles. Password values are not part of this lookup.`
          : "Titles and data classes only. Password values are not part of this lookup.",
      source: { name: "Have I Been Pwned", url: "https://haveibeenpwned.com/API/v3" },
      confidence: "observed",
    },
    ...shown.map((breach) => ({
      title: breach.Title || breach.Name || "Untitled breach",
      severity: breach.IsVerified === false ? ("low" as const) : ("medium" as const),
      summary: breach.BreachDate ? `Breach date ${breach.BreachDate}.` : "No breach date was listed.",
      evidence: [
        breach.Name ? { label: "Name", value: breach.Name } : undefined,
        breach.DataClasses?.length
          ? { label: "Data classes", value: breach.DataClasses.slice(0, 12).join(", ") }
          : undefined,
      ].filter((row): row is EvidenceRow => Boolean(row)),
      source: { name: "Have I Been Pwned", url: "https://haveibeenpwned.com/" },
    })),
  ]);
}

export function countPwnedSuffix(body: string, suffix: string): number {
  const wanted = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [found, count] = line.trim().split(":");
    if (found?.toUpperCase() === wanted) {
      const parsed = Number(count);
      return Number.isFinite(parsed) ? parsed : 0;
    }
  }
  return 0;
}

export async function collectPasswordRange(password: string): Promise<Finding[]> {
  const digest = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = digest.slice(0, 5);
  const suffix = digest.slice(5);
  const response = await fetchPublic(`https://api.pwnedpasswords.com/range/${prefix}`, {
    maxBytes: 512_000,
    timeoutMs: 10_000,
    headers: { "Add-Padding": "true" },
  });
  if (response.status >= 400) {
    throw new Error(`Pwned Passwords returned HTTP ${response.status}.`);
  }
  const count = countPwnedSuffix(response.body, suffix);
  const graded = passwordRangeSummary(count);
  return stamp("password-range", [
    {
      ...graded,
      evidence: [{ label: "Range prefix sent", value: `${prefix} (five characters of a SHA-1 hash)` }],
      source: { name: "Pwned Passwords", url: "https://haveibeenpwned.com/Passwords" },
    },
  ]);
}

export async function collectPhone(number: string): Promise<Finding[]> {
  const phone = parsePhoneNumberFromString(number);
  if (!phone?.isValid()) {
    throw new Error("That phone number is not valid in libphonenumber.");
  }
  return stamp("phone-format", [
    {
      title: "International format",
      severity: "info",
      summary: `${phone.formatInternational()} is a valid ${phone.getType() ?? "number"} in ${phone.country ?? "an unknown region"}.`,
      evidence: [
        { label: "Country", value: phone.country ?? "unknown" },
        { label: "Type", value: phone.getType() ?? "unknown" },
        { label: "E.164", value: phone.number },
      ],
      source: { name: "libphonenumber metadata", url: "https://github.com/google/libphonenumber" },
      confidence: "inferred",
    },
    {
      title: "No live handset lookup",
      severity: "info",
      summary: "Lantern does not query carriers, HLR databases, or messaging apps for this number.",
      source: { name: "Lantern", url: "" },
      confidence: "inferred",
    },
  ]);
}

export async function collectReverseDns(ip: string): Promise<Finding[]> {
  if (isPrivateAddress(ip)) throw new Error("Private and reserved addresses are not queried.");
  try {
    const names = await reverse(ip);
    return stamp("reverse-dns", [
      {
        title: names.length ? "PTR records" : "No PTR record",
        severity: "info",
        summary: names.length ? names.slice(0, 8).join(", ") : `${ip} has no PTR record in this resolver.`,
        evidence: names.slice(0, 8).map((name) => ({ label: "PTR", value: name })),
        source: { name: "Reverse DNS", url: "" },
      },
    ]);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENOTFOUND" || code === "ENODATA") {
      return stamp("reverse-dns", [
        {
          title: "No PTR record",
          severity: "info",
          summary: `${ip} has no PTR record in this resolver.`,
          source: { name: "Reverse DNS", url: "" },
        },
      ]);
    }
    throw new Error(`Reverse DNS failed${code ? ` (${code})` : ""}.`);
  }
}

type IpWho = {
  success?: boolean;
  message?: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  connection?: { asn?: number; org?: string };
};

export async function collectGeolocation(ip: string): Promise<Finding[]> {
  if (isPrivateAddress(ip)) throw new Error("Private and reserved addresses are not queried.");
  const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
  const response = await fetchPublic(url, { maxBytes: 20_000, timeoutMs: 8_000, headers: { accept: "application/json" } });
  if (response.status >= 400) throw new Error(`ipwho.is returned HTTP ${response.status}.`);
  const document = JSON.parse(response.body) as IpWho;
  if (document.success === false) {
    throw new Error(document.message || "ipwho.is could not place this address.");
  }
  return stamp("geolocation", [
    {
      title: "Coarse network location",
      severity: "info",
      summary: [document.city, document.region, document.country].filter(Boolean).join(", ") || "No place name was returned.",
      evidence: [
        document.country ? { label: "Country", value: document.country } : undefined,
        document.region ? { label: "Region", value: document.region } : undefined,
        document.city ? { label: "City", value: document.city } : undefined,
        document.isp ? { label: "ISP", value: document.isp } : undefined,
        document.connection?.asn ? { label: "ASN", value: String(document.connection.asn) } : undefined,
        document.connection?.org ? { label: "Network", value: document.connection.org } : undefined,
      ].filter((row): row is EvidenceRow => Boolean(row)),
      source: { name: "ipwho.is", url },
    },
  ]);
}
