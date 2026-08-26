import type { DataValue } from "@opencomputer/agent";

export type DependabotTrigger = {
  event: "github.dependabot.alert.open";
  repositoryId: number;
  alertNumber: number;
  alertUpdatedAt: string;
};

type JsonRecord = Record<string, DataValue>;

function record(value: DataValue | undefined): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

export function parseDependabotTrigger(
  value: DataValue | undefined,
): DependabotTrigger | undefined {
  const payload = record(value);
  if (payload.event !== "github.dependabot.alert.open") return undefined;
  if (
    typeof payload.repositoryId !== "number" ||
    !Number.isSafeInteger(payload.repositoryId) ||
    payload.repositoryId <= 0 ||
    typeof payload.alertNumber !== "number" ||
    !Number.isSafeInteger(payload.alertNumber) ||
    payload.alertNumber <= 0 ||
    typeof payload.alertUpdatedAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(payload.alertUpdatedAt)
  ) {
    return undefined;
  }
  return {
    event: payload.event,
    repositoryId: payload.repositoryId,
    alertNumber: payload.alertNumber,
    alertUpdatedAt: payload.alertUpdatedAt,
  };
}
