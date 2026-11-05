# Stellwerk web panel

React 19 + TypeScript (strict) + Vite single-page app for the Stellwerk server
(see `../docs/ARCHITECTURE.md` §5.6). It talks only to the REST API in
`../api/openapi.yaml` and two WebSockets (`/api/v1/events`, shell sessions).

## Commands

```bash
npm ci               # install exact versions from package-lock.json
npm run dev          # Vite on :5173, proxies /api (incl. WebSockets) to http://localhost:8080
npm run gen:api      # regenerate src/api/schema.d.ts from ../api/openapi.yaml (commit the result)
npm run typecheck    # tsc -b
npm run lint         # eslint (typescript-eslint, react-hooks, security rules)
npm test             # vitest
npm run build        # typecheck + production build into dist/
```

The Go server embeds `dist/` and serves it with a strict CSP
(`script-src 'self'`, `connect-src 'self'`, no inline scripts). The build emits
no inline scripts/styles and no `eval`; fonts are the system font stack.

In development the session cookie is `__Host-`-prefixed and `Secure`; browsers
accept it on `http://localhost`. A backend that checks the `Origin` of WebSocket
upgrades must allow `http://localhost:5173` in dev mode.

## Layout

```
src/api/         openapi-fetch client, CSRF middleware, error envelope, queries, events socket
src/auth/        login state machine, MFA (WebAuthn/TOTP), step-up dialog, permissions hook
src/app/         shell (sidebar/top bar), theme, router root
src/components/  ui/ (shadcn-style on Radix), common/ (states, badges, dialogs, …)
src/features/    pages: dashboard, hosts (+ tabs), jobs, updates, security, alerts, admin, account, shell
src/lib/         pure helpers with unit tests (base64url, webauthn, asciicast, format, permissions, …)
```

## Security notes

- Auth is the server's HttpOnly session cookie; nothing is stored in Web Storage
  except the theme preference. The CSRF token from `GET /auth/session` is kept in
  the query cache and sent as `X-CSRF-Token` on every state-changing request.
- `unauthenticated` → login; `stepup_required` → step-up dialog (WebAuthn or TOTP),
  then the request is retried once; `forbidden` → friendly message.
- Server-provided text (job output, inventory, audit details, recordings) is
  rendered as text only. ESLint forbids `dangerouslySetInnerHTML`/`innerHTML`.
- Permission checks in the UI only hide or disable actions; the server re-checks.
