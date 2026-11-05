# 0007 — React + TypeScript + Vite web panel

- Status: accepted
- Date: 2026-11-05

## Decision
React with strict TypeScript, Vite, TanStack Query/Router, Tailwind + shadcn-style components, xterm.js for the terminal and uPlot for charts. The API client is generated from `api/openapi.yaml` (openapi-typescript + openapi-fetch). The production build is embedded into the server binary (`-tags webui`) and served under a strict CSP.

## Consequences
No inline scripts and no third-party origins. Session tokens live only in HttpOnly cookies; the CSRF token is kept in memory.
