import { registerOutbox } from "@opencomputer/agent";
import security from "../../../outboxes/security.js";

export default registerOutbox(security);
