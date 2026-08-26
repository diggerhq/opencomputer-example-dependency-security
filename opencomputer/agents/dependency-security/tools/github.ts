import {
  bearer,
  type DataValue,
  defineConnection,
  defineTool,
  useSecret,
} from "@opencomputer/agent";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { PUBLISH_ENABLED, TARGET_REPOSITORY } from "../config.js";
import {
  auditNpmDependencyUpdate,
  commitSha,
  ghsaId,
  npmPackageName,
  repositoryBranch,
  repositorySegment,
} from "./policy.js";

const execFileAsync = promisify(execFile);
const REPOSITORY_ROOT = "/workspace/repositories";
const BASELINE_ROOT = "/workspace/repository-baselines";

const reviewedAlerts = new Map<string, { alertNumber: number; headSha: string }>();
const materializedAlerts = new Map<string, { alertNumber: number; headSha: string }>();

const owner = repositorySegment(TARGET_REPOSITORY.owner, "configured owner");
const repository = repositorySegment(TARGET_REPOSITORY.repository, "configured repository");
const defaultBranch = repositoryBranch(TARGET_REPOSITORY.defaultBranch);

const github = defineConnection({
  id: "github-dependency-security",
  origin: "https://api.github.com",
  methods: ["GET", "POST", "PUT"],
  pathPrefix: "/repos/",
  redirectOrigins: [
    {
      origin: "https://codeload.github.com",
      pathPrefix: "/",
    },
  ],
  headers: {
    Accept: "application/vnd.github+json",
    Authorization: bearer(useSecret("GITHUB_PAT")),
    "User-Agent": "opencomputer-example-dependency-security",
    "X-GitHub-Api-Version": "2026-03-10",
  },
});

type GitHubRepository = { id: number; default_branch: string };
type GitHubRef = { object: { sha: string } };
type GitHubCommit = { sha: string; tree: { sha: string } };
type GitHubTree = { sha: string };
type GitHubBlob = { sha: string };
type GitHubOpenPull = { number: number; html_url: string };
export type DependabotAlert = {
  number: number;
  state: string;
  html_url: string;
  updated_at: string;
  dependency: {
    package: { ecosystem: string; name: string };
    manifest_path: string;
    scope: string;
    relationship?: string;
  };
  security_advisory: {
    ghsa_id: string;
    cve_id: string | null;
    summary: string;
    description: string;
    severity: string;
    references: Array<{ url: string }>;
    cwes: Array<{ cwe_id: string; name: string }>;
  };
  security_vulnerability: {
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  };
};

export type ValidatedAlert = {
  alert: DependabotAlert;
  headSha: string;
  packageName: string;
  ghsa: string;
  vulnerableRange: string;
  firstPatchedVersion: string;
};

export type AuthoritativeAlert = {
  alert: DependabotAlert;
  headSha: string;
};

function checkoutPath(): string {
  return resolve(REPOSITORY_ROOT, `${owner}--${repository}`);
}

function baselinePath(): string {
  return resolve(BASELINE_ROOT, `${owner}--${repository}`);
}

async function githubResponse(path: string, init?: RequestInit, allowNotFound = false): Promise<Response | undefined> {
  const response = await github.fetch(path, init);
  if (allowNotFound && response.status === 404) return undefined;
  if (!response.ok) {
    const message = await response.text();
    throw new Error(`GitHub API ${response.status}: ${message.slice(0, 2_000)}`);
  }
  return response;
}

async function githubJson<T>(path: string, init?: RequestInit, allowNotFound = false): Promise<T | undefined> {
  const response = await githubResponse(path, init, allowNotFound);
  return response ? (await response.json()) as T : undefined;
}

function jsonRequest(method: "POST" | "PUT", body: unknown, signal?: AbortSignal): RequestInit {
  return {
    method,
    signal,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

function alertNumber(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error("alertNumber must be a positive integer");
  return number;
}

export async function readAuthoritativeAlert(
  numberValue: unknown,
  signal?: AbortSignal,
): Promise<AuthoritativeAlert> {
  const number = alertNumber(numberValue);
  const metadata = await githubJson<GitHubRepository>(`/repos/${owner}/${repository}`, { signal });
  if (metadata!.id !== TARGET_REPOSITORY.repositoryId) {
    throw new Error("The code-configured GitHub repository ID does not match");
  }
  if (metadata!.default_branch !== defaultBranch) {
    throw new Error("The code-configured default branch does not match GitHub");
  }
  const [alert, head] = await Promise.all([
    githubJson<DependabotAlert>(`/repos/${owner}/${repository}/dependabot/alerts/${number}`, { signal }),
    githubJson<GitHubRef>(`/repos/${owner}/${repository}/git/ref/heads/${encodeURIComponent(defaultBranch)}`, { signal }),
  ]);
  if (alert!.number !== number || alert!.state !== "open") throw new Error("Dependabot alert is not open");
  return { alert: alert!, headSha: commitSha(head!.object.sha) };
}

export async function readValidatedAlert(numberValue: unknown, signal?: AbortSignal): Promise<ValidatedAlert> {
  const authoritative = await readAuthoritativeAlert(numberValue, signal);
  const { alert, headSha } = authoritative;
  if (alert.dependency.package.ecosystem.toLowerCase() !== "npm") throw new Error("This example supports npm alerts only");
  if (alert.dependency.manifest_path !== TARGET_REPOSITORY.manifestPath) {
    throw new Error("Dependabot alert does not belong to the configured manifest");
  }
  if (alert.dependency.relationship !== "direct") {
    throw new Error("This example supports direct dependency alerts only");
  }
  const firstPatchedVersion = alert.security_vulnerability.first_patched_version?.identifier;
  if (!firstPatchedVersion) throw new Error("Dependabot does not identify a patched npm version");
  return {
    alert,
    headSha,
    packageName: npmPackageName(alert.dependency.package.name),
    ghsa: ghsaId(alert.security_advisory.ghsa_id),
    vulnerableRange: alert.security_vulnerability.vulnerable_version_range,
    firstPatchedVersion,
  };
}

export const getDependencyAlert = defineTool({
  name: "get_dependency_alert",
  description: "Retrieve and validate one open npm Dependabot alert and the exact configured default-branch head.",
  input: {
    type: "object",
    properties: { alertNumber: { type: "integer", minimum: 1 } },
    required: ["alertNumber"],
    additionalProperties: false,
  },
  async run({ input, sessionId, signal }): Promise<DataValue> {
    const result = await readValidatedAlert(input.alertNumber, signal);
    reviewedAlerts.set(sessionId, {
      alertNumber: result.alert.number,
      headSha: result.headSha,
    });
    materializedAlerts.delete(sessionId);
    return {
      alertNumber: result.alert.number,
      alertUrl: result.alert.html_url,
      alertUpdatedAt: result.alert.updated_at,
      repository: `${owner}/${repository}`,
      defaultBranch,
      headSha: result.headSha,
      dependency: {
        package: result.packageName,
        manifestPath: result.alert.dependency.manifest_path,
        scope: result.alert.dependency.scope,
        relationship: result.alert.dependency.relationship ?? "unknown",
        vulnerableRange: result.vulnerableRange,
        firstPatchedVersion: result.firstPatchedVersion,
      },
      advisory: {
        ghsa: result.ghsa,
        cve: result.alert.security_advisory.cve_id ?? "",
        severity: result.alert.security_advisory.severity,
        summary: result.alert.security_advisory.summary,
        description: result.alert.security_advisory.description,
        cwes: result.alert.security_advisory.cwes.map((cwe) => ({ id: cwe.cwe_id, name: cwe.name })),
        references: result.alert.security_advisory.references.map((reference) => reference.url),
      },
    };
  },
});

export const materializeConfiguredRepository = defineTool({
  name: "materialize_configured_repository",
  description: "Download the configured repository at the exact analyzed head and create a private baseline for dependency-only publication.",
  input: {
    type: "object",
    properties: {},
    additionalProperties: false,
  },
  async run({ sessionId, signal, reportProgress }) {
    const reviewed = reviewedAlerts.get(sessionId);
    if (!reviewed) {
      throw new Error("No reviewed Dependabot alert is available. Call get_dependency_alert first.");
    }
    const ref = reviewed.headSha;
    materializedAlerts.delete(sessionId);
    const metadata = await githubJson<GitHubRepository>(`/repos/${owner}/${repository}`, { signal });
    const head = await githubJson<GitHubRef>(`/repos/${owner}/${repository}/git/ref/heads/${encodeURIComponent(defaultBranch)}`, { signal });
    if (metadata!.id !== TARGET_REPOSITORY.repositoryId || head!.object.sha !== ref) {
      throw new Error("Requested snapshot is not the current configured default-branch head");
    }
    const destination = checkoutPath();
    const baseline = baselinePath();
    const temporary = await mkdtemp(join(tmpdir(), "dependency-security-repository-"));
    const archive = join(temporary, "repository.tar.gz");
    await reportProgress({ status: "downloading", repository: `${owner}/${repository}`, ref });
    try {
      const response = await github.fetch(`/repos/${owner}/${repository}/tarball/${encodeURIComponent(ref)}`, { signal });
      if (!response.ok) throw new Error(`GitHub archive failed with ${response.status}`);
      await writeFile(archive, new Uint8Array(await response.arrayBuffer()));
      await mkdir(REPOSITORY_ROOT, { recursive: true });
      await mkdir(BASELINE_ROOT, { recursive: true });
      await rm(destination, { recursive: true, force: true });
      await rm(baseline, { recursive: true, force: true });
      await mkdir(destination, { recursive: true });
      await execFileAsync("tar", ["-xzf", archive, "--strip-components=1", "-C", destination], { signal });
      await cp(destination, baseline, { recursive: true, dereference: false });
      materializedAlerts.set(sessionId, reviewed);
      return { repository: `${owner}/${repository}`, ref, path: destination };
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  },
});

export const openSecurityPullRequest = defineTool({
  name: "open_security_pull_request",
  description: "Mechanically verify an npm-only security update, atomically publish it to a deterministic branch, and create or reuse a pull request.",
  input: {
    type: "object",
    properties: {
      alertNumber: { type: "integer", minimum: 1 },
      baseSha: { type: "string", pattern: "^[0-9a-fA-F]{40}$" },
      title: { type: "string", minLength: 1, maxLength: 200 },
      body: { type: "string", minLength: 1, maxLength: 20_000 },
      commitMessage: { type: "string", minLength: 1, maxLength: 200 },
      dryRun: { type: "boolean", default: false },
    },
    required: ["alertNumber", "baseSha", "title", "body", "commitMessage"],
    additionalProperties: false,
  },
  async run({ input, sessionId, signal, reportProgress }): Promise<DataValue> {
    const baseSha = commitSha(input.baseSha);
    const materialized = materializedAlerts.get(sessionId);
    if (!materialized) {
      throw new Error("No materialized alert snapshot is available in this session.");
    }
    if (materialized.alertNumber !== Number(input.alertNumber) || materialized.headSha !== baseSha) {
      throw new Error("The requested alert and head do not match this session's materialized snapshot.");
    }
    const validated = await readValidatedAlert(input.alertNumber, signal);
    if (validated.headSha !== baseSha) throw new Error("Default branch advanced after analysis; restart from the new head");
    const body = String(input.body).trim();
    for (const section of ["Exposure evidence", "Dependency update", "Validation", "Residual risk"]) {
      if (!body.toLowerCase().includes(section.toLowerCase())) throw new Error(`Pull-request body is missing: ${section}`);
    }
    const branch = `security/${validated.ghsa.toLowerCase()}-${baseSha.slice(0, 12)}`;
    const audit = await auditNpmDependencyUpdate({
      baselineRoot: baselinePath(),
      workingRoot: checkoutPath(),
      manifestPath: TARGET_REPOSITORY.manifestPath,
      lockfilePath: TARGET_REPOSITORY.lockfilePath,
      packageName: validated.packageName,
      vulnerableRange: validated.vulnerableRange,
      firstPatchedVersion: validated.firstPatchedVersion,
    });
    if (!PUBLISH_ENABLED || input.dryRun === true) {
      return {
        status: "dry-run",
        repository: `${owner}/${repository}`,
        base: defaultBranch,
        baseSha,
        branch,
        previousVersions: audit.previousVersions,
        patchedVersions: audit.patchedVersions,
        files: audit.files.map((file) => ({ path: file.path, bytes: file.bytes })),
      };
    }
    const existing = await githubJson<GitHubOpenPull[]>(
      `/repos/${owner}/${repository}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}&base=${encodeURIComponent(defaultBranch)}`,
      { signal },
    );
    if (existing?.length) return { status: "existing", number: existing[0].number, url: existing[0].html_url, branch };

    const existingBranch = await githubJson<GitHubRef>(
      `/repos/${owner}/${repository}/git/ref/heads/${encodeURIComponent(branch)}`,
      { signal },
      true,
    );
    if (existingBranch) throw new Error("Deterministic security branch exists without an open pull request; refusing to overwrite it");

    await reportProgress({ status: "publishing", files: audit.files.map((file) => file.path) });
    const baseCommit = await githubJson<GitHubCommit>(`/repos/${owner}/${repository}/git/commits/${baseSha}`, { signal });
    const treeEntries = [];
    for (const file of audit.files) {
      const blob = await githubJson<GitHubBlob>(
        `/repos/${owner}/${repository}/git/blobs`,
        jsonRequest("POST", { content: file.content, encoding: "utf-8" }, signal),
      );
      treeEntries.push({ path: file.path, mode: "100644", type: "blob", sha: blob!.sha });
    }
    const tree = await githubJson<GitHubTree>(
      `/repos/${owner}/${repository}/git/trees`,
      jsonRequest("POST", { base_tree: baseCommit!.tree.sha, tree: treeEntries }, signal),
    );
    const commit = await githubJson<GitHubCommit>(
      `/repos/${owner}/${repository}/git/commits`,
      jsonRequest("POST", { message: String(input.commitMessage).trim(), tree: tree!.sha, parents: [baseSha] }, signal),
    );
    await githubJson(
      `/repos/${owner}/${repository}/git/refs`,
      jsonRequest("POST", { ref: `refs/heads/${branch}`, sha: commit!.sha }, signal),
    );
    const pull = await githubJson<GitHubOpenPull>(
      `/repos/${owner}/${repository}/pulls`,
      jsonRequest("POST", {
        title: String(input.title).trim(),
        body,
        head: branch,
        base: defaultBranch,
        draft: false,
      }, signal),
    );
    return {
      status: "created",
      number: pull!.number,
      url: pull!.html_url,
      branch,
      previousVersions: audit.previousVersions,
      patchedVersions: audit.patchedVersions,
    };
  },
});
