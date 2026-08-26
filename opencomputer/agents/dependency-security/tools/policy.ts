import { isDeepStrictEqual } from "node:util";
import { lstat, readFile, readdir, readlink } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import semver from "semver";

const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".mypy_cache",
  ".pytest_cache",
  ".venv",
  "__pycache__",
  "coverage",
  "node_modules",
  "venv",
]);

type JsonObject = Record<string, unknown>;

export type AuditedDependencyFile = {
  readonly path: string;
  readonly content: string;
  readonly bytes: number;
};

export type DependencyAudit = {
  readonly files: readonly AuditedDependencyFile[];
  readonly previousVersions: readonly string[];
  readonly patchedVersions: readonly string[];
};

export function repositorySegment(value: unknown, label: string): string {
  const normalized = String(value ?? "").trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(normalized)) {
    throw new Error(`${label} contains unsupported characters`);
  }
  return normalized;
}

export function npmPackageName(value: unknown): string {
  const normalized = String(value ?? "").trim();
  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(normalized)) {
    throw new Error("alerted npm package contains unsupported characters");
  }
  return normalized;
}

export function repositoryBranch(value: unknown): string {
  const normalized = String(value ?? "").trim();
  if (
    !/^[A-Za-z0-9._/-]+$/.test(normalized) ||
    normalized.startsWith("/") ||
    normalized.endsWith("/") ||
    normalized.includes("//") ||
    normalized.includes("..")
  ) {
    throw new Error("configured default branch contains unsupported characters");
  }
  return normalized;
}

export function repositoryFilePath(value: unknown): string {
  const normalized = String(value ?? "").trim().replace(/^\.\//, "");
  if (
    !normalized ||
    normalized.startsWith("/") ||
    normalized.includes("\\") ||
    normalized.includes("\0")
  ) {
    throw new Error(`Invalid repository file path: ${JSON.stringify(value)}`);
  }
  const segments = normalized.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error(`Invalid repository file path: ${JSON.stringify(value)}`);
  }
  return segments.join("/");
}

export function commitSha(value: unknown): string {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(normalized)) {
    throw new Error("baseSha must be a full 40-character Git commit SHA");
  }
  return normalized;
}

export function ghsaId(value: unknown): string {
  const normalized = String(value ?? "").trim().toUpperCase();
  if (!/^GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}$/.test(normalized)) {
    throw new Error("Invalid GHSA identifier");
  }
  return normalized;
}

export function npmRange(value: unknown): string {
  const normalized = String(value ?? "").trim().replace(/,/g, " ");
  if (!normalized || semver.validRange(normalized, { loose: true }) === null) {
    throw new Error("Dependabot returned an unsupported npm vulnerable range");
  }
  return normalized;
}

function object(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as JsonObject;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function removeDependencyFromGroups(container: JsonObject, packageName: string): void {
  for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const dependencies = container[group];
    if (dependencies && typeof dependencies === "object" && !Array.isArray(dependencies)) {
      delete (dependencies as JsonObject)[packageName];
    }
  }
}

function directDependencySpec(manifest: JsonObject, packageName: string): string | undefined {
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const dependencies = manifest[group];
    if (dependencies && typeof dependencies === "object" && !Array.isArray(dependencies)) {
      const value = (dependencies as JsonObject)[packageName];
      if (typeof value === "string") return value;
    }
  }
  return undefined;
}

function lockPackageName(path: string, metadata: JsonObject): string | undefined {
  if (typeof metadata.name === "string") return metadata.name;
  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  if (index < 0) return undefined;
  const remainder = path.slice(index + marker.length);
  const segments = remainder.split("/");
  return segments[0]?.startsWith("@")
    ? segments.slice(0, 2).join("/")
    : segments[0];
}

function dependencyVersions(lockfile: JsonObject, packageName: string): string[] {
  const packages = object(lockfile.packages, "package-lock packages");
  const versions = new Set<string>();
  for (const [path, rawMetadata] of Object.entries(packages)) {
    if (!rawMetadata || typeof rawMetadata !== "object" || Array.isArray(rawMetadata)) continue;
    const metadata = rawMetadata as JsonObject;
    if (lockPackageName(path, metadata) === packageName && typeof metadata.version === "string") {
      versions.add(metadata.version);
    }
  }
  return [...versions].sort();
}

function stripTargetFromLockfile(lockfile: JsonObject, packageName: string): JsonObject {
  const stripped = clone(lockfile);
  const packages = object(stripped.packages, "package-lock packages");
  for (const [path, rawMetadata] of Object.entries(packages)) {
    if (!rawMetadata || typeof rawMetadata !== "object" || Array.isArray(rawMetadata)) continue;
    const metadata = rawMetadata as JsonObject;
    if (path === "") removeDependencyFromGroups(metadata, packageName);
    if (lockPackageName(path, metadata) === packageName) delete packages[path];
  }
  const legacyDependencies = stripped.dependencies;
  if (legacyDependencies && typeof legacyDependencies === "object" && !Array.isArray(legacyDependencies)) {
    delete (legacyDependencies as JsonObject)[packageName];
  }
  return stripped;
}

async function manifest(root: string): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  async function visit(relative: string): Promise<void> {
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && SKIPPED_DIRECTORIES.has(entry.name)) continue;
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      const absolute = join(root, ...path.split("/"));
      const stat = await lstat(absolute);
      if (stat.isDirectory()) await visit(path);
      else if (stat.isFile()) {
        const bytes = await readFile(absolute);
        result.set(path, `file:${createHash("sha256").update(bytes).digest("hex")}`);
      } else if (stat.isSymbolicLink()) result.set(path, `symlink:${await readlink(absolute)}`);
      else result.set(path, `other:${stat.mode}`);
    }
  }
  await visit("");
  return result;
}

async function readJson(path: string, label: string): Promise<JsonObject> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${String(error)}`);
  }
  return object(parsed, label);
}

export async function auditNpmDependencyUpdate(options: {
  baselineRoot: string;
  workingRoot: string;
  manifestPath: string;
  lockfilePath: string;
  packageName: string;
  vulnerableRange: string;
  firstPatchedVersion: string;
}): Promise<DependencyAudit> {
  const manifestPath = repositoryFilePath(options.manifestPath);
  const lockfilePath = repositoryFilePath(options.lockfilePath);
  const packageName = npmPackageName(options.packageName);
  const vulnerableRange = npmRange(options.vulnerableRange);
  const firstPatchedVersion = semver.valid(options.firstPatchedVersion, { loose: true });
  if (!firstPatchedVersion) throw new Error("Dependabot returned an invalid first patched version");

  const [baselineFiles, workingFiles] = await Promise.all([
    manifest(options.baselineRoot),
    manifest(options.workingRoot),
  ]);
  const allowed = new Set([manifestPath, lockfilePath]);
  const changed: string[] = [];
  for (const path of new Set([...baselineFiles.keys(), ...workingFiles.keys()])) {
    if (baselineFiles.get(path) !== workingFiles.get(path)) changed.push(path);
  }
  if (!changed.length) throw new Error("The dependency snapshot is unchanged");
  for (const path of changed) {
    if (!allowed.has(path)) throw new Error(`Snapshot includes an unauthorized change: ${path}`);
    if (!workingFiles.get(path)?.startsWith("file:")) {
      throw new Error(`Dependency updates must remain regular files: ${path}`);
    }
  }
  if (!changed.includes(lockfilePath)) throw new Error("The package lockfile must change");

  const [baselineManifest, workingManifest, baselineLock, workingLock] = await Promise.all([
    readJson(join(options.baselineRoot, ...manifestPath.split("/")), "baseline package.json"),
    readJson(join(options.workingRoot, ...manifestPath.split("/")), "working package.json"),
    readJson(join(options.baselineRoot, ...lockfilePath.split("/")), "baseline package-lock.json"),
    readJson(join(options.workingRoot, ...lockfilePath.split("/")), "working package-lock.json"),
  ]);
  if (!directDependencySpec(baselineManifest, packageName)) {
    throw new Error(`${packageName} is not a direct dependency in the configured manifest`);
  }
  if (!directDependencySpec(workingManifest, packageName)) {
    throw new Error(`${packageName} was removed instead of patched`);
  }

  const baselineManifestWithoutTarget = clone(baselineManifest);
  const workingManifestWithoutTarget = clone(workingManifest);
  removeDependencyFromGroups(baselineManifestWithoutTarget, packageName);
  removeDependencyFromGroups(workingManifestWithoutTarget, packageName);
  if (!isDeepStrictEqual(baselineManifestWithoutTarget, workingManifestWithoutTarget)) {
    throw new Error("package.json contains changes unrelated to the alerted dependency");
  }
  if (!isDeepStrictEqual(
    stripTargetFromLockfile(baselineLock, packageName),
    stripTargetFromLockfile(workingLock, packageName),
  )) {
    throw new Error("package-lock.json contains changes to unrelated dependencies or metadata");
  }

  const previousVersions = dependencyVersions(baselineLock, packageName);
  const patchedVersions = dependencyVersions(workingLock, packageName);
  if (!previousVersions.some((version) => semver.satisfies(version, vulnerableRange, { includePrerelease: true, loose: true }))) {
    throw new Error(`The baseline lockfile does not contain a vulnerable ${packageName} version`);
  }
  if (!patchedVersions.length) throw new Error(`The working lockfile does not install ${packageName}`);
  for (const version of patchedVersions) {
    if (
      semver.satisfies(version, vulnerableRange, { includePrerelease: true, loose: true }) ||
      !semver.gte(version, firstPatchedVersion, { loose: true })
    ) {
      throw new Error(`${packageName}@${version} is not demonstrably patched`);
    }
  }

  const files: AuditedDependencyFile[] = [];
  for (const path of changed.sort()) {
    const bytes = await readFile(join(options.workingRoot, ...path.split("/")));
    if (bytes.byteLength > 2_000_000) throw new Error(`Dependency file exceeds 2 MB: ${path}`);
    files.push({ path, content: bytes.toString("utf8"), bytes: bytes.byteLength });
  }
  return { files, previousVersions, patchedVersions };
}
