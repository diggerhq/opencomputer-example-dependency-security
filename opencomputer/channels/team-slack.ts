import { defineChannel } from "@opencomputer/agent";

export default defineChannel({
  id: "team-slack",
  type: "slack",
  displayName: "Security Slack",
  scopes: {
    bot: ["channels:read", "chat:write"],
  },
  destinations: {
    security: {
      type: "conversation",
      visibility: "public",
    },
  },
});
