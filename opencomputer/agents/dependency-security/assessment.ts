export function redactCredentialShapes(value: string): string {
  return value
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]{20,}={0,2}\b/gi, "$1[REDACTED_TOKEN]");
}

function requiredText(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty string`);
  return redactCredentialShapes(value.trim().slice(0, maximum));
}

function textList(value: unknown, name: string, minimum: number, maximum: number): string[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${name} must contain between ${minimum} and ${maximum} strings`);
  }
  return value.map((item, index) => requiredText(item, `${name}[${index}]`, 800));
}

export function securityAssessmentContent(input: {
  disposition?: unknown;
  cve?: unknown;
  ghsa?: unknown;
  packageName?: unknown;
  vulnerableRange?: unknown;
  affectedBehavior?: unknown;
  reasoning?: unknown;
  evidence?: unknown;
  unknowns?: unknown;
  alertUrl: string;
}) {
  const disposition = input.disposition;
  if (disposition !== "not-exposed" && disposition !== "needs-review") {
    throw new Error("disposition must be not-exposed or needs-review");
  }
  const evidence = textList(input.evidence, "evidence", 1, 8);
  const unknowns = textList(input.unknowns, "unknowns", disposition === "needs-review" ? 1 : 0, 6);
  return {
    title: `${requiredText(input.cve || input.ghsa, "CVE or GHSA", 100)}: ${disposition}`,
    body: requiredText(input.reasoning, "reasoning", 2_000),
    url: input.alertUrl,
    disposition,
    ghsa: requiredText(input.ghsa, "ghsa", 100),
    cve: typeof input.cve === "string" && input.cve.trim()
      ? requiredText(input.cve, "cve", 100)
      : "",
    package: requiredText(input.packageName, "packageName", 214),
    vulnerableRange: requiredText(input.vulnerableRange, "vulnerableRange", 300),
    affectedBehavior: requiredText(input.affectedBehavior, "affectedBehavior", 1_500),
    evidence,
    unknowns,
  };
}
