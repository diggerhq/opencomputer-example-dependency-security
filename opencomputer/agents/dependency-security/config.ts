export const TARGET_REPOSITORY = {
  owner: "your-github-owner",
  repository: "your-repository",
  repositoryId: 123_456_789,
  defaultBranch: "main",
  manifestPath: "package.json",
  lockfilePath: "package-lock.json",
} as const;

// Keep publishing disabled until a dry run against a disposable fixture has
// produced the intended dependency-only change and passed its test commands.
export const PUBLISH_ENABLED = false;
