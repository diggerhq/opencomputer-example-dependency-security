import { defineOutbox } from "@opencomputer/agent";
import teamSlack from "../channels/team-slack.js";

export default defineOutbox({
  id: "security",
  delivery: {
    channel: teamSlack,
    destination: "security",
  },
});
