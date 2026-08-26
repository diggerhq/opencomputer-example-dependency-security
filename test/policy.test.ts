import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  auditNpmDependencyUpdate,
  ghsaId,
  npmPackageName,
  npmRange,
  repositoryFilePath,
} from "../opencomputer/agents/dependency-security/tools/policy.ts";

type Fixture = { baseline: string; working: string; cleanup(): Promise<void> };

function packageJson(version = "^1.0.0", extra = {}) {
  return { name: "fixture", private: true, dependencies: { vulnerable: version }, ...extra };
}

function packageLock(version = "1.0.0", extraPackage: unknown = undefined) {
  return {
    name: "fixture",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture", dependencies: { vulnerable: `^${version}` } },
      "node_modules/vulnerable": {
        version,
        resolved: `https://registry.npmjs.org/vulnerable/-/vulnerable-${version}.tgz`,
        integrity: `sha512-${version}`,
      },
      ...(extraPackage ? { "node_modules/unrelated": extraPackage } : {}),
    },
  };
}

async function fixture(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "dependency-security-policy-"));
  const baseline = join(root, "baseline");
  const working = join(root, "working");
  await mkdir(baseline);
  await writeFile(join(baseline, "package.json"), JSON.stringify(packageJson(), null, 2));
  await writeFile(join(baseline, "package-lock.json"), JSON.stringify(packageLock(), null, 2));
  await mkdir(join(baseline, "src"));
  await writeFile(join(baseline, "src", "index.ts"), "export const value = 1;\n");
  await cp(baseline, working, { recursive: true });
  return { baseline, working, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function audit(files: Fixture) {
  return auditNpmDependencyUpdate({
    baselineRoot: files.baseline,
    workingRoot: files.working,
    manifestPath: "package.json",
    lockfilePath: "package-lock.json",
    packageName: "vulnerable",
    vulnerableRange: ">= 1.0.0, < 1.0.1",
    firstPatchedVersion: "1.0.1",
  });
}

test("validates paths, scoped npm names, ranges, and GHSA IDs", () => {
  assert.equal(repositoryFilePath("./package.json"), "package.json");
  assert.throws(() => repositoryFilePath("../package.json"), /Invalid/);
  assert.equal(npmPackageName("@scope/package"), "@scope/package");
  assert.throws(() => npmPackageName("bad/package/name"), /unsupported/);
  assert.equal(npmRange(">= 1.0.0, < 1.0.1"), ">= 1.0.0  < 1.0.1");
  assert.equal(ghsaId("GHSA-2345-6789-CFGH"), "GHSA-2345-6789-CFGH");
});

test("accepts a focused update that removes every vulnerable version", async () => {
  const files = await fixture();
  try {
    await writeFile(join(files.working, "package.json"), JSON.stringify(packageJson("^1.0.1"), null, 2));
    await writeFile(join(files.working, "package-lock.json"), JSON.stringify(packageLock("1.0.1"), null, 2));
    const result = await audit(files);
    assert.deepEqual(result.previousVersions, ["1.0.0"]);
    assert.deepEqual(result.patchedVersions, ["1.0.1"]);
    assert.deepEqual(result.files.map((file) => file.path), ["package-lock.json", "package.json"]);
  } finally {
    await files.cleanup();
  }
});

test("rejects a still-vulnerable update", async () => {
  const files = await fixture();
  try {
    await writeFile(join(files.working, "package-lock.json"), JSON.stringify(packageLock("1.0.0-beta.1"), null, 2));
    await assert.rejects(audit(files), /not demonstrably patched/);
  } finally {
    await files.cleanup();
  }
});

test("rejects production files and unrelated dependency churn", async () => {
  const production = await fixture();
  try {
    await writeFile(join(production.working, "package.json"), JSON.stringify(packageJson("^1.0.1"), null, 2));
    await writeFile(join(production.working, "package-lock.json"), JSON.stringify(packageLock("1.0.1"), null, 2));
    await writeFile(join(production.working, "src", "index.ts"), "export const value = 2;\n");
    await assert.rejects(audit(production), /unauthorized change: src\/index.ts/);
  } finally {
    await production.cleanup();
  }

  const churn = await fixture();
  try {
    await writeFile(join(churn.working, "package.json"), JSON.stringify(packageJson("^1.0.1"), null, 2));
    await writeFile(join(churn.working, "package-lock.json"), JSON.stringify(packageLock("1.0.1", {
      version: "2.0.0",
    }), null, 2));
    await assert.rejects(audit(churn), /unrelated dependencies or metadata/);
  } finally {
    await churn.cleanup();
  }
});

test("rejects removal of the direct dependency", async () => {
  const files = await fixture();
  try {
    await writeFile(join(files.working, "package.json"), JSON.stringify({ name: "fixture", private: true }, null, 2));
    await writeFile(join(files.working, "package-lock.json"), JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: { "": { name: "fixture" } },
    }, null, 2));
    await assert.rejects(audit(files), /removed instead of patched/);
  } finally {
    await files.cleanup();
  }
});
