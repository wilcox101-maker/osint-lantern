import type { Severity } from "./types";

export type HeaderGrade = {
  severity: Severity;
  title: string;
  summary: string;
  remediation?: string;
};

function header(headers: Headers, name: string): string {
  return headers.get(name)?.trim() ?? "";
}

export function gradeHeaders(headers: Headers): HeaderGrade[] {
  const grades: HeaderGrade[] = [];
  const hsts = header(headers, "strict-transport-security");
  const csp = header(headers, "content-security-policy");
  const nosniff = header(headers, "x-content-type-options");
  const frame = header(headers, "x-frame-options");
  const referrer = header(headers, "referrer-policy");
  const permissions = header(headers, "permissions-policy");
  const server = header(headers, "server");
  const powered = header(headers, "x-powered-by");

  if (!hsts) {
    grades.push({
      severity: "medium",
      title: "HSTS is not published",
      summary: "The response did not include Strict-Transport-Security.",
      remediation: "Send Strict-Transport-Security on HTTPS responses so browsers stay on TLS.",
    });
  } else {
    grades.push({
      severity: "info",
      title: "HSTS is published",
      summary: hsts.slice(0, 180),
    });
  }

  if (!csp) {
    grades.push({
      severity: "low",
      title: "Content-Security-Policy is absent",
      summary: "No Content-Security-Policy header was returned.",
      remediation: "Publish a Content-Security-Policy that fits the pages you actually serve.",
    });
  } else {
    grades.push({
      severity: "info",
      title: "Content-Security-Policy is present",
      summary: "A Content-Security-Policy header was returned.",
    });
  }

  if (nosniff.toLowerCase() !== "nosniff") {
    grades.push({
      severity: "low",
      title: "MIME sniffing is not disabled",
      summary: "X-Content-Type-Options was missing or was not nosniff.",
      remediation: "Set X-Content-Type-Options to nosniff.",
    });
  }

  const framed =
    frame.length > 0 || /frame-ancestors/i.test(csp);
  if (!framed) {
    grades.push({
      severity: "low",
      title: "Framing is not restricted",
      summary: "Neither X-Frame-Options nor a CSP frame-ancestors directive was present.",
      remediation: "Set X-Frame-Options or CSP frame-ancestors so other sites cannot frame this response.",
    });
  }

  if (!referrer) {
    grades.push({
      severity: "info",
      title: "Referrer-Policy is absent",
      summary: "The response did not set Referrer-Policy.",
      remediation: "Set Referrer-Policy, often to strict-origin-when-cross-origin.",
    });
  }

  if (!permissions) {
    grades.push({
      severity: "info",
      title: "Permissions-Policy is absent",
      summary: "The response did not set Permissions-Policy.",
    });
  }

  if (server || powered) {
    grades.push({
      severity: "info",
      title: "Server software is named",
      summary: [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`]
        .filter(Boolean)
        .join(" · ")
        .slice(0, 240),
      remediation: "Remove version banners you do not need visitors to see.",
    });
  }

  return grades;
}

export function gradeSpf(records: string[]): HeaderGrade {
  const spf = records.filter((record) => record.toLowerCase().startsWith("v=spf1"));
  if (spf.length === 0) {
    return {
      severity: "medium",
      title: "No SPF policy is published",
      summary: "No TXT record starting with v=spf1 was found.",
      remediation: "Publish one SPF record that lists the servers allowed to send mail for this domain.",
    };
  }
  if (spf.length > 1) {
    return {
      severity: "medium",
      title: "More than one SPF record is published",
      summary: "Receivers treat multiple SPF records as a permanent error.",
      remediation: "Keep a single TXT record that starts with v=spf1.",
    };
  }
  const policy = spf[0].toLowerCase();
  if (policy.includes("+all") || /(?:^|\s)all(?:\s|$)/.test(policy)) {
    return {
      severity: "high",
      title: "SPF allows any sender",
      summary: spf[0].slice(0, 240),
      remediation: "Replace the all mechanism with a hard fail or a soft fail after the real senders.",
    };
  }
  if (policy.includes("-all")) {
    return {
      severity: "info",
      title: "SPF hard-fails other senders",
      summary: spf[0].slice(0, 240),
    };
  }
  if (policy.includes("~all")) {
    return {
      severity: "low",
      title: "SPF soft-fails other senders",
      summary: spf[0].slice(0, 240),
      remediation: "Move to -all once you know every legitimate sender is included.",
    };
  }
  return {
    severity: "low",
    title: "SPF does not end in a clear all mechanism",
    summary: spf[0].slice(0, 240),
    remediation: "End the SPF record with ~all or -all.",
  };
}

export function gradeDmarc(record: string | null): HeaderGrade {
  if (!record) {
    return {
      severity: "medium",
      title: "No DMARC policy is published",
      summary: "No DMARC TXT record was found at _dmarc.",
      remediation: "Publish a DMARC record. Start with p=none while you read reports, then move to quarantine or reject.",
    };
  }
  const policy = /(?:^|;)\s*p\s*=\s*(reject|quarantine|none)/i.exec(record)?.[1]?.toLowerCase();
  if (policy === "reject") {
    return {
      severity: "info",
      title: "DMARC rejects unaligned mail",
      summary: record.slice(0, 240),
    };
  }
  if (policy === "quarantine") {
    return {
      severity: "info",
      title: "DMARC quarantines unaligned mail",
      summary: record.slice(0, 240),
    };
  }
  if (policy === "none") {
    return {
      severity: "low",
      title: "DMARC is monitoring only",
      summary: record.slice(0, 240),
      remediation: "After the reports look right, change p=none to p=quarantine or p=reject.",
    };
  }
  return {
    severity: "low",
    title: "DMARC policy could not be read",
    summary: record.slice(0, 240),
    remediation: "Publish a DMARC record with p=none, p=quarantine, or p=reject.",
  };
}

export function passwordRangeSummary(count: number): {
  severity: Severity;
  title: string;
  summary: string;
  remediation?: string;
} {
  if (!Number.isFinite(count) || count < 0) {
    return {
      severity: "info",
      title: "Password range result was unreadable",
      summary: "The range API answered, but the count could not be read.",
    };
  }
  if (count > 0) {
    return {
      severity: "high",
      title: "Password appeared in the public corpus",
      summary: `This password appeared ${count.toLocaleString("en-US")} times in the public Pwned Passwords corpus.`,
      remediation:
        "Stop using this password. Replace it with a unique one, including anywhere it was reused.",
    };
  }
  return {
    severity: "info",
    title: "Password was not in the public corpus",
    summary: "This password did not appear in the public Pwned Passwords corpus.",
  };
}
