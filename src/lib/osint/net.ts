import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

import { isReservedHostname } from "./classify";

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("10.0.0.0", 8, "ipv4");
blocked.addSubnet("100.64.0.0", 10, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("172.16.0.0", 12, "ipv4");
blocked.addSubnet("192.0.0.0", 24, "ipv4");
blocked.addSubnet("192.0.2.0", 24, "ipv4");
blocked.addSubnet("192.168.0.0", 16, "ipv4");
blocked.addSubnet("198.18.0.0", 15, "ipv4");
blocked.addSubnet("198.51.100.0", 24, "ipv4");
blocked.addSubnet("203.0.113.0", 24, "ipv4");
blocked.addSubnet("224.0.0.0", 4, "ipv4");
blocked.addSubnet("240.0.0.0", 4, "ipv4");
blocked.addAddress("::", "ipv6");
blocked.addAddress("::1", "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");
blocked.addSubnet("ff00::", 8, "ipv6");
blocked.addSubnet("2001:db8::", 32, "ipv6");

export function isPrivateAddress(address: string): boolean {
  const normalized = address.split("%")[0];
  const mapped = normalized.toLowerCase().startsWith("::ffff:")
    ? normalized.slice(7)
    : normalized;
  const kind = isIP(mapped);
  if (kind === 0) return true;
  return blocked.check(mapped, kind === 4 ? "ipv4" : "ipv6");
}

export async function assertPublicHostname(hostname: string): Promise<void> {
  const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!host || isReservedHostname(host)) {
    throw new Error("That host is local, reserved, or not a public name.");
  }
  if (isIP(host)) {
    if (isPrivateAddress(host)) {
      throw new Error("Private and reserved addresses are not queried.");
    }
    return;
  }
  const records = await lookup(host, { all: true, verbatim: true });
  if (records.length === 0) {
    throw new Error("The name did not resolve.");
  }
  for (const record of records) {
    if (isPrivateAddress(record.address)) {
      throw new Error("That name resolves to a private or reserved address.");
    }
  }
}

export type PublicResponse = {
  status: number;
  headers: Headers;
  body: string;
  finalUrl: string;
  truncated: boolean;
};

export async function fetchPublic(
  input: string,
  init: {
    method?: "GET" | "HEAD";
    headers?: Record<string, string>;
    maxBytes?: number;
    timeoutMs?: number;
    onOverflow?: "error" | "truncate";
  } = {},
  redirects = 0,
): Promise<PublicResponse> {
  const url = new URL(input);
  if (url.username || url.password) {
    throw new Error("URLs with credentials are refused.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only http and https URLs are fetched.");
  }
  const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
  if (port !== 80 && port !== 443) {
    throw new Error("Only ports 80 and 443 are fetched.");
  }
  await assertPublicHostname(url.hostname);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? 8000);
  try {
    const response = await fetch(url, {
      method: init.method ?? "GET",
      redirect: "manual",
      signal: controller.signal,
      cache: "no-store",
      headers: {
        "user-agent": "LanternOSINT/0.1 (local research workstation)",
        accept: "*/*",
        ...init.headers,
      },
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) throw new Error("A redirect was missing its location.");
      if (redirects >= 3) throw new Error("Too many redirects.");
      return fetchPublic(new URL(location, url).toString(), init, redirects + 1);
    }

    const method = init.method ?? "GET";
    const chunks: Uint8Array[] = [];
    let truncated = false;
    if (method !== "HEAD" && response.body) {
      const reader = response.body.getReader();
      const max = init.maxBytes ?? 48_000;
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        received += value.byteLength;
        if (received > max) {
          await reader.cancel();
          if (init.onOverflow === "truncate") {
            truncated = true;
            break;
          }
          throw new Error("The response was larger than Lantern will keep.");
        }
        chunks.push(value);
      }
    }

    return {
      status: response.status,
      headers: response.headers,
      body: Buffer.concat(chunks).toString("utf8"),
      finalUrl: url.toString(),
      truncated,
    };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("The request timed out.");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
