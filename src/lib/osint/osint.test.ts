import { describe, expect, it } from "vitest";

import { classifySelector, isReservedHostname, isRoleMailbox } from "./classify";
import { countPwnedSuffix } from "./collect";
import { isPrivateAddress } from "./net";
import { gradeDmarc, gradeSpf, passwordRangeSummary } from "./posture";
import { toMarkdown } from "./report";
import type { Investigation } from "./types";

describe("classifySelector", () => {
  it("recognizes the public target shapes", () => {
    expect(classifySelector(" Ada@Example.com ")).toEqual({
      ok: true,
      kind: "email",
      value: "ada@example.com",
    });
    expect(classifySelector("https://Example.com/docs")).toEqual({
      ok: true,
      kind: "domain",
      value: "example.com",
    });
    expect(classifySelector("8.8.8.8")).toMatchObject({ ok: true, kind: "ip" });
    expect(classifySelector("+1 415 555 2671")).toMatchObject({ ok: true, kind: "phone" });
    expect(classifySelector("ada_lovelace")).toMatchObject({ ok: true, kind: "username" });
    expect(classifySelector("alice.smith")).toMatchObject({ ok: true, kind: "username" });
  });

  it("rejects empty and private-looking local names at the name layer", () => {
    expect(classifySelector("  ").ok).toBe(false);
    expect(isReservedHostname("printer.local")).toBe(true);
    expect(isReservedHostname("example.com")).toBe(false);
    expect(classifySelector("http://printer.local").ok).toBe(false);
    expect(classifySelector("metadata.google.internal").ok).toBe(false);
  });
});

describe("address guard", () => {
  it("blocks reserved ranges used for metadata and loopback", () => {
    expect(isPrivateAddress("169.254.169.254")).toBe(true);
    expect(isPrivateAddress("10.1.2.3")).toBe(true);
    expect(isPrivateAddress("127.0.0.1")).toBe(true);
    expect(isPrivateAddress("::1")).toBe(true);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
    expect(isPrivateAddress("2001:4860:4860::8888")).toBe(false);
  });
});

describe("mail policy grades", () => {
  it("flags an SPF record that lets every host send", () => {
    expect(gradeSpf(["v=spf1 +all"]).severity).toBe("high");
    expect(gradeSpf([]).severity).toBe("medium");
    expect(gradeSpf(["v=spf1 include:_spf.example.com -all"]).severity).toBe("info");
  });

  it("reads the DMARC policy tag", () => {
    expect(gradeDmarc(null).severity).toBe("medium");
    expect(gradeDmarc("v=DMARC1; p=none").severity).toBe("low");
    expect(gradeDmarc("v=DMARC1; p=reject").severity).toBe("info");
  });
});

describe("password range", () => {
  it("counts only the matching suffix and never echoes a password", () => {
    const body = "ABCDEF0123456789:12\n00112233445566778899AABBCCDDEEFF:3\n";
    expect(countPwnedSuffix(body, "00112233445566778899AABBCCDDEEFF")).toBe(3);
    expect(countPwnedSuffix(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")).toBe(0);
    const summary = passwordRangeSummary(12);
    expect(summary.summary).toContain("12");
    expect(summary.summary.toLowerCase()).not.toContain("password123");
    expect(isRoleMailbox("security@example.com")).toBe(true);
  });
});

describe("report", () => {
  it("records that a password was checked without a place to store it", () => {
    const investigation: Investigation = {
      id: "11111111-1111-4111-8111-111111111111",
      createdAt: "2026-10-21T00:00:00.000Z",
      label: "ada@example.com",
      selector: "email",
      value: "ada@example.com",
      notes: "",
      passwordChecked: true,
      modules: [],
      findings: [],
    };
    const markdown = toMarkdown(investigation);
    expect(markdown).toContain("the value was not stored");
    expect(JSON.stringify(investigation)).not.toContain("password123");
  });
});
