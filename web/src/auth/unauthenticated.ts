// Global "session ended" hook. Registered by the app shell once the router
// exists; called from the query/mutation caches whenever the API answers
// `unauthenticated`.

type Handler = () => void;

let handler: Handler | null = null;

export function setUnauthenticatedHandler(h: Handler | null): void {
  handler = h;
}

export function notifyUnauthenticated(): void {
  handler?.();
}
