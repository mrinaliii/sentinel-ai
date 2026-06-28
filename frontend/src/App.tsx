/**
 * SentinelAI — App Root
 *
 * Sets up:
 *  - BrowserRouter (React Router v7)
 *  - QueryClientProvider (TanStack Query v5)
 *  - ReactQueryDevtools (dev only)
 *  - AppRouter
 */

import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { AppRouter } from "./router";

// TanStack Query client with sensible defaults for a security dashboard:
//  - staleTime: 30s — security data changes frequently
//  - retry: 1 — fail fast in security context
//  - refetchOnWindowFocus: true — always get fresh data on tab return
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
    mutations: {
      retry: 0,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppRouter />
      </BrowserRouter>
      {import.meta.env.DEV && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  );
}
