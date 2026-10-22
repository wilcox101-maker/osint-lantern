import { parsePhoneNumberFromString } from "libphonenumber-js";

import type { ClassifiedSelector, SelectorKind } from "./types";

const EMAIL =
  /^[a-z0-9._%+-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const HOST =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const USERNAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/;

const LONG_TLDS = new Set([
  "com",
  "net",
  "org",
  "io",
  "dev",
  "app",
  "ai",
  "info",
  "biz",
  "xyz",
  "me",
  "tv",
  "gov",
  "mil",
  "edu",
  "cloud",
  "tech",
  "online",
  "site",
  "store",
  "blog",
  "studio",
  "design",
  "systems",
  "security",
  "email",
  "name",
  "pro",
  "agency",
  "network",
  "software",
  "page",
  "live",
  "news",
  "media",
  "social",
  "tools",
]);

const ROLE_LOCALS = new Set([
  "admin",
  "administrator",
  "billing",
  "contact",
  "hello",
  "help",
  "info",
  "mail",
  "marketing",
  "noreply",
  "no-reply",
  "office",
  "postmaster",
  "privacy",
  "sales",
  "security",
  "support",
  "team",
  "webmaster",
]);

export function isRoleMailbox(email: string): boolean {
  const local = email.split("@")[0]?.toLowerCase() ?? "";
  return ROLE_LOCALS.has(local);
}

const RESERVED_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".lan"];

export function isReservedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!host || host === "localhost") return true;
  if (RESERVED_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  if (!host.includes(".") || /^\d+$/.test(host) || host.startsWith("0x")) return true;
  return false;
}

export function isDomainName(host: string): boolean {
  if (!HOST.test(host)) return false;
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  const tld = labels[labels.length - 1] ?? "";
  if (tld.length === 2) return true;
  return LONG_TLDS.has(tld);
}

function punycodeHost(host: string): string | null {
  try {
    return new URL(`http://${host}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function classifySelector(raw: string): ClassifiedSelector {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, error: "Enter an email, domain, IP, username, or phone number." };
  if (trimmed.length > 200) return { ok: false, error: "That value is too long." };

  let candidate = trimmed;
  if (/^https?:\/\//i.test(candidate)) {
    try {
      candidate = new URL(candidate).hostname;
    } catch {
      return { ok: false, error: "That website URL could not be parsed." };
    }
  }
  candidate = candidate.replace(/\.$/, "");

  if (!candidate.includes("@") && candidate.includes(".") && isReservedHostname(candidate)) {
    return {
      ok: false,
      error: "That name is local or reserved. Lantern only queries public hosts.",
    };
  }

  if (candidate.includes("@")) {
    const email = candidate.toLowerCase();
    if (!EMAIL.test(email) || !isDomainName(email.split("@")[1] ?? "")) {
      return { ok: false, error: "Enter a full email address, such as ada@example.com." };
    }
    return { ok: true, kind: "email", value: email };
  }

  if (isIp(candidate)) {
    return { ok: true, kind: "ip", value: candidate.toLowerCase() };
  }

  const phone = parsePhoneNumberFromString(candidate);
  if (candidate.startsWith("+") || phone?.isValid()) {
    if (!phone?.isValid()) {
      return {
        ok: false,
        error: "Enter a phone number with a country code, such as +1 415 555 2671.",
      };
    }
    return { ok: true, kind: "phone", value: phone.number };
  }

  const host = punycodeHost(candidate);
  if (host && isDomainName(host)) {
    return { ok: true, kind: "domain", value: host };
  }

  if (USERNAME.test(candidate) && !candidate.includes("..")) {
    return { ok: true, kind: "username", value: candidate };
  }

  return {
    ok: false,
    error:
      "Lantern could not tell what that is. Use a full email, a site such as example.com, a public IP, a username, or a phone number that starts with +.",
  };
}

function isIp(value: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split(".").every((part) => {
      const n = Number(part);
      return n >= 0 && n <= 255 && String(n) === String(Number(part));
    });
  }
  return value.includes(":") && /^[0-9a-f:]+$/i.test(value) && value.split(":").length > 2;
}

export function selectorLabel(kind: SelectorKind): string {
  switch (kind) {
    case "email":
      return "Email";
    case "domain":
      return "Domain";
    case "ip":
      return "IP address";
    case "username":
      return "Username";
    case "phone":
      return "Phone";
  }
}
