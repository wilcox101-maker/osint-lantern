import type { SelectorKind } from "./types";

export type CatalogModule = {
  id: string;
  title: string;
  selectors: SelectorKind[];
  requiresPassword?: boolean;
  observed: string;
  does: string;
};

/**
 * Capability map taken from a passive REA pass on 21 Oct 2026.
 * REA 6.7.0 attached to local headless Chrome and ran list-browser-targets
 * plus inspect-web-page with accessibility text only. Script sources and
 * storage were not collected. analyze-web-bundle on the login app exhausted
 * memory, so authenticated routes were not copied.
 *
 * Public pages read: pentester.com, /checker/, /services/, faq.pentester.com,
 * npd.pentester.com, app.pentester.com/login, and osintpilot.com.
 */
export const CATALOG_MODULES: CatalogModule[] = [
  {
    id: "mailbox",
    title: "Mailbox shape",
    selectors: ["email"],
    observed: "Email field on the public breach checker",
    does: "Checks the address shape and flags shared mailboxes such as info@ or admin@.",
  },
  {
    id: "dns",
    title: "DNS footprint",
    selectors: ["domain", "email"],
    observed: "Website scan and digital-footprint copy on the public marketing site",
    does: "Collects published A, AAAA, MX, NS, and TXT records.",
  },
  {
    id: "mail-auth",
    title: "Mail authentication",
    selectors: ["domain", "email"],
    observed: "Email exposure check",
    does: "Reads the published SPF and DMARC policies. DKIM selectors are not guessed.",
  },
  {
    id: "registration",
    title: "Registration record",
    selectors: ["domain", "email", "ip"],
    observed: "Domain and IP recon described for the public scanner",
    does: "Reads the public RDAP record for a domain or IP.",
  },
  {
    id: "certificates",
    title: "Certificate names",
    selectors: ["domain", "email"],
    observed: "Digital footprint of company technology",
    does: "Lists hostnames published in Certificate Transparency logs. Cert Spotter is tried first, then crt.sh.",
  },
  {
    id: "http-posture",
    title: "HTTP posture",
    selectors: ["domain", "email"],
    observed: "Publicly known website issues, with fix guidance, on the marketing site",
    does: "Requests the site once and grades common security headers. No exploit payloads are sent.",
  },
  {
    id: "published-files",
    title: "Published files",
    selectors: ["domain", "email"],
    observed: "Website scan",
    does: "Fetches /robots.txt and /.well-known/security.txt.",
  },
  {
    id: "gravatar",
    title: "Gravatar",
    selectors: ["email"],
    observed: "Account footprint tied to an email",
    does: "Checks whether a public Gravatar image exists for the address.",
  },
  {
    id: "public-profiles",
    title: "Public profile URLs",
    selectors: ["username"],
    observed: "Social profile identification named in the public FAQ, and footprint mapping on OSINT Pilot",
    does: "Requests a fixed list of public profile URLs. HTTP 200 is a candidate, not proof of control.",
  },
  {
    id: "breach-names",
    title: "Breach names",
    selectors: ["email"],
    observed: "Breach exposure checker and OSINT Pilot breach intelligence",
    does: "When HIBP_API_KEY is set, asks Have I Been Pwned for breach titles and data classes. Password values are never requested.",
  },
  {
    id: "password-range",
    title: "Password range",
    selectors: ["email", "domain", "ip", "username", "phone"],
    requiresPassword: true,
    observed: "Public checker copy about whether a password has appeared in a leak",
    does: "Hashes a password you type and sends only the first five SHA-1 characters to the Pwned Passwords range API. The password is not stored.",
  },
  {
    id: "phone-format",
    title: "Phone format",
    selectors: ["phone"],
    observed: "Phone as an investigation input on OSINT Pilot",
    does: "Parses an international number with libphonenumber. No carrier or live handset lookup.",
  },
  {
    id: "reverse-dns",
    title: "Reverse DNS",
    selectors: ["ip"],
    observed: "IP recon",
    does: "Looks up PTR records for a public IP address.",
  },
  {
    id: "geolocation",
    title: "Network location",
    selectors: ["ip"],
    observed: "IP recon",
    does: "Reads country, region, city, and network name from ipwho.is. Coordinates are not stored.",
  },
];

export const OUT_OF_SCOPE = [
  {
    name: "Exploitation and red team modules",
    why: "The public services page lists penetration testing and red teaming. Lantern does not send attack payloads or map exploit paths.",
  },
  {
    name: "National ID and date-of-birth search",
    why: "npd.pentester.com exposes an SSN breach form. Lantern does not accept social security numbers or dates of birth.",
  },
  {
    name: "Password and stealer-log retrieval",
    why: "The checker talks about leaked passwords and a large breach corpus. Lantern reports counts and breach titles only.",
  },
  {
    name: "DarkWatch and IdentityIQ",
    why: "The public FAQ names both tools inside the signed-in Tools area. Their implementations were not read and are not recreated.",
  },
  {
    name: "Data-broker removal and portal automation",
    why: "OSINT Pilot describes browser agents that fill government forms. Lantern does not browse portals or file removal requests.",
  },
];

export function moduleTitle(id: string): string {
  return CATALOG_MODULES.find((item) => item.id === id)?.title ?? id;
}

export function modulesFor(
  kind: SelectorKind,
  passwordProvided: boolean,
): CatalogModule[] {
  return CATALOG_MODULES.filter((item) => {
    if (!item.selectors.includes(kind)) return false;
    if (item.requiresPassword && !passwordProvided) return false;
    return true;
  });
}
