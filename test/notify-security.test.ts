import assert from "node:assert/strict";
import test from "node:test";
import {
  redactCredentialShapes,
  securityAssessmentContent,
} from "../opencomputer/agents/dependency-security/assessment.ts";

const base = {
  cve: "CVE-2026-1234",
  ghsa: "GHSA-2345-6789-CFGH",
  packageName: "vulnerable",
  vulnerableRange: ">=1.0.0 <1.0.1",
  affectedBehavior: "parse() is vulnerable only with the unsafe option.",
  reasoning: "Every call sets unsafe to false through one wrapper.",
  evidence: ["src/parser.ts:12 is the only import and passes unsafe: false"],
  unknowns: [],
  alertUrl: "https://github.com/acme/widgets/security/dependabot/42",
};

test("builds a bounded non-exposure report", () => {
  const content = securityAssessmentContent({ ...base, disposition: "not-exposed" });
  assert.equal(content.disposition, "not-exposed");
  assert.equal(content.package, "vulnerable");
  assert.deepEqual(content.unknowns, []);
});

test("supports advisories that have only a GHSA identifier", () => {
  const content = securityAssessmentContent({
    ...base,
    cve: "",
    disposition: "not-exposed",
  });
  assert.equal(content.title, "GHSA-2345-6789-CFGH: not-exposed");
  assert.equal(content.cve, "");
});

test("requires an unknown for needs-review and rejects exposed", () => {
  assert.throws(
    () => securityAssessmentContent({ ...base, disposition: "needs-review" }),
    /unknowns must contain/,
  );
  assert.throws(
    () => securityAssessmentContent({ ...base, disposition: "exposed" }),
    /disposition/,
  );
});

test("redacts credential-shaped text", () => {
  assert.equal(
    redactCredentialShapes("Bearer abcdefghijklmnopqrstuvwxyz.123456"),
    "Bearer [REDACTED_TOKEN]",
  );
});
