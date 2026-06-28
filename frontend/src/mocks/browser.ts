/**
 * SentinelAI — MSW Browser Setup
 *
 * Aggregates all route handlers and exports the service worker instance.
 * Import and call `worker.start()` in main.tsx during development.
 */

import { setupWorker } from "msw/browser";
import { alertHandlers } from "./handlers/alerts";
import { incidentHandlers } from "./handlers/incidents";
import { dashboardHandlers, mitreHandlers, chatHandlers } from "./handlers/misc";

export const worker = setupWorker(
  ...alertHandlers,
  ...incidentHandlers,
  ...dashboardHandlers,
  ...mitreHandlers,
  ...chatHandlers
);
