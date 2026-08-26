import assert from "node:assert/strict";
import test from "node:test";
import { parseDependabotTrigger } from "../opencomputer/agents/dependency-security/trigger.ts";

test("parses a normalized Dependabot trigger", () => {
  assert.deepEqual(parseDependabotTrigger({
    event: "github.dependabot.alert.open",
    repositoryId: 123456789,
    alertNumber: 42,
    alertUpdatedAt: "2026-08-24T12:00:00Z",
  }), {
    event: "github.dependabot.alert.open",
    repositoryId: 123456789,
    alertNumber: 42,
    alertUpdatedAt: "2026-08-24T12:00:00Z",
  });
});

test("rejects malformed or unrelated triggers", () => {
  assert.equal(parseDependabotTrigger({ event: "push" }), undefined);
  assert.equal(parseDependabotTrigger({
    event: "github.dependabot.alert.open",
    repositoryId: 1,
    alertNumber: 0,
    alertUpdatedAt: "yesterday",
  }), undefined);
});
