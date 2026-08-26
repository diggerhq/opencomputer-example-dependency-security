import { defineTool, publishOutbox } from "@opencomputer/agent";
import { TARGET_REPOSITORY } from "../config.js";
import { securityAssessmentContent } from "../assessment.js";
import { assertMaterializedAlert, readAuthoritativeAlert } from "./github.js";

type Disposition = "not-exposed" | "needs-review";

export const notifySecurity = defineTool({
  name: "notify_security_assessment",
  description: "Publish one non-exposure or needs-review assessment to the configured security Slack destination, then stop.",
  input: {
    type: "object",
    properties: {
      alertNumber: { type: "integer", minimum: 1 },
      disposition: { type: "string", enum: ["not-exposed", "needs-review"] },
      affectedBehavior: { type: "string", minLength: 1 },
      reasoning: { type: "string", minLength: 1 },
      evidence: { type: "array", minItems: 1, maxItems: 8, items: { type: "string" } },
      unknowns: { type: "array", minItems: 0, maxItems: 6, items: { type: "string" } },
    },
    required: ["alertNumber", "disposition", "affectedBehavior", "reasoning", "evidence", "unknowns"],
    additionalProperties: false,
  },
  async run({ input, sessionId, signal }) {
    const authoritative = await readAuthoritativeAlert(input.alertNumber, signal);
    const alert = authoritative.alert;
    assertMaterializedAlert(sessionId, alert.number, authoritative.headSha);
    const content = securityAssessmentContent({
      ...input,
      cve: alert.security_advisory.cve_id ?? "",
      ghsa: alert.security_advisory.ghsa_id,
      packageName: alert.dependency.package.name,
      vulnerableRange: alert.security_vulnerability.vulnerable_version_range,
      alertUrl: alert.html_url,
    });
    const result = await publishOutbox("security", {
      type: "github.dependabot.exposure-assessed",
      content: {
        ...content,
        repository: `${TARGET_REPOSITORY.owner}/${TARGET_REPOSITORY.repository}`,
        alertNumber: alert.number,
      },
      idempotencyKey: `dependency-security-assessment:${sessionId}`,
    });
    return { id: result.id, status: result.status, duplicate: result.duplicate };
  },
});
