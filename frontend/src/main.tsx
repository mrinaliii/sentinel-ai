/**
 * SentinelAI — Entry Point
 *
 * Starts MSW in development, then renders the React app.
 * MSW intercepts all /api/v1/* requests before they reach the network.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";

async function enableMocking() {
  if (import.meta.env.DEV) {
    const { worker } = await import("./mocks/browser");
    return worker.start({
      onUnhandledRequest: "bypass", // don't warn on non-API requests (fonts, etc.)
    });
  }
  return Promise.resolve();
}

const root = document.getElementById("root");
if (!root) throw new Error("Root element #root not found in index.html");

enableMocking().then(() => {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>
  );
});
