# OpenComputer dependency security agent

This example checks whether an npm Dependabot alert is exploitable in one
configured repository. If application code reaches the affected API, the agent
bumps only the alerted dependency, runs the repository's tests, and opens a
pull request. If the affected behavior is provably unreachable, it explains
why in a bound `#security` Slack conversation and stops. Ambiguous evidence is
reported as `needs-review`, never as safe.

## Decision flow

```text
Open Dependabot alert
        |
        v
Advisory + exact default-branch snapshot
        |
        v
Affected API and call-path analysis
        |
        +-- exposed ------> npm-only bump -> tests -> guarded PR
        |
        +-- not exposed --> evidence report to #security -> stop
        |
        +-- uncertain ----> needs-review report to #security -> stop
```

The first version deliberately supports direct npm dependencies in one root
`package.json` and npm v2/v3 `package-lock.json`. That lets the publishing tool
mechanically reject unrelated file or dependency changes and verify that no
installed version still matches the vulnerable semver range.

## Prerequisites

- Node.js 22 or newer
- an OpenComputer project
- Dependabot alerts enabled for the target GitHub repository
- a fine-grained GitHub token for the agent with **Contents: read and write**,
  **Pull requests: read and write**, and **Dependabot alerts: read**
- a separate fine-grained token or GitHub App token for the collector with
  **Dependabot alerts: read**
- a Slack workspace where the OpenComputer channel app can post to a public
  `#security` conversation

GitHub's built-in Actions `GITHUB_TOKEN` cannot read Dependabot alerts. Store
the collector's read-only token as `DEPENDABOT_READ_TOKEN`; do not broaden the
workflow token.

## Configure the fixed repository

Edit `opencomputer/agents/dependency-security/config.ts`:

```ts
export const TARGET_REPOSITORY = {
  owner: "your-github-owner",
  repository: "your-repository",
  repositoryId: 123456789,
  defaultBranch: "main",
  manifestPath: "package.json",
  lockfilePath: "package-lock.json",
} as const;

export const PUBLISH_ENABLED = false;
```

Find the immutable numeric repository ID from GitHub's repository API. The
owner, name, ID, branch, and paths are code-owned; alert text and repository
contents cannot redirect the agent.

Keep `PUBLISH_ENABLED` set to `false` for the first exposed-path run. The agent
still audits the dependency-only edit and reports the deterministic branch and
files, but the tool does not write a branch or pull request. Set it to `true`
only after reviewing a successful dry run against a disposable fixture.

## Run the agent in Development

```bash
npm ci
npm test
npm run build
npm run opencomputer -- link
npm run opencomputer -- secrets set GITHUB_PAT --environment development --agent current
npm run dev
```

In the Development project dashboard, connect Slack, bind the code-defined
`security` destination to the public `#security` conversation, and verify the
binding.

Create an authenticated webhook for the agent:

```bash
npm run opencomputer -- webhooks create dependabot-alerts \
  --agent current \
  --environment development
```

Store the returned values in the target repository as:

- `OPENCOMPUTER_WEBHOOK_URL`
- `OPENCOMPUTER_WEBHOOK_TOKEN`

Also store the collector token as `DEPENDABOT_READ_TOKEN`. Copy
`templates/collect-dependabot-alerts.yml` to the target repository's
`.github/workflows/` directory. It polls every 15 minutes and can be run
manually. Unchanged
alerts reuse a stable idempotency key, so repeated polls do not start duplicate
sessions. GitHub may delay scheduled workflows; this example does not promise
instant delivery.

## Guardrails

The agent retrieves the authoritative alert and exact repository head through
a destination-constrained GitHub connection. The repository archive is never
cloned with a credential. Publishing rejects:

- transitive, non-npm, closed, unpatched, or differently manifested alerts;
- a repository ID, default branch, or head that no longer matches;
- any change outside the configured manifest and lockfile;
- removed dependencies, symlinks, unrelated manifest fields, or unrelated
  lockfile packages;
- a lockfile that still contains a vulnerable or pre-patch version; and
- an existing deterministic branch without an open pull request.

The agent explicitly enables the runtime-provided `read` and `shell` tools and
allows non-interactive filesystem access inside its isolated microVM. The
materialized repository lives outside OpenCode's initial working directory;
without this permission, a headless run can stall waiting for an approval that
cannot be answered. Repository files and npm scripts are untrusted code, so use
a disposable target for initial validation, keep the PAT scoped to that one
repository, and review the dry-run result before enabling publication. GitHub
API access and publishing remain confined to the code-defined tools.

The agent cannot dismiss alerts, merge PRs, or post an exposed result as a
no-exposure Slack message. A failed or unavailable test becomes a needs-review
notification and no PR.

## Verify locally

```bash
npm test
npm run build
```

Before treating this as production-ready, exercise both fixture outcomes
end-to-end: one reachable vulnerable call that opens exactly one PR, and one
provably unreachable call that produces exactly one Slack report. Inspect the
OpenComputer session events, PR, and Slack message for credential leakage.
