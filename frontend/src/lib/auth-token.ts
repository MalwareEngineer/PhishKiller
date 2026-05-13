/**
 * Module-level access-token plumbing for the API client.
 *
 * The OIDC `AuthProvider` registers a getter once at mount time; the
 * API client (`lib/api.ts`) reads from it before each outgoing request.
 * Module-level state (rather than threading the token through every
 * call site) keeps the existing `kits.list()` / `actors.get()` API
 * surface unchanged.
 *
 * In disabled mode the getter is never registered → `getAuthHeaders()`
 * returns an empty object → requests go out anonymously, which is the
 * correct behavior for the backend's disabled mode.
 */

let accessTokenGetter: (() => string | null) | null = null;

/**
 * Called once by `AuthProvider` (auth-enabled path) on mount.  Passing
 * a function rather than the token itself means the API client always
 * sees the freshest token after silent refresh — no "stale token in
 * closure" footgun.
 */
export function setAccessTokenGetter(getter: () => string | null): void {
  accessTokenGetter = getter;
}

/**
 * Returns the headers object to merge into outgoing API requests.
 * Empty when auth is disabled or no token is present yet (e.g. during
 * the brief window between provider mount and first silent-signin
 * resolution).
 */
export function getAuthHeaders(): Record<string, string> {
  const token = accessTokenGetter?.();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Test-only.  Reset the registered getter between test cases. */
export function _resetAuthTokenForTests(): void {
  accessTokenGetter = null;
}
