/**
 * Auth context provider — single source of truth for the UI's auth state.
 *
 * Two distinct modes selected at provider mount based on `readOidcEnv()`:
 *
 * 1. **Disabled** (`VITE_AUTH_ENABLED!=="true"`) — the provider is a
 *    pass-through.  `user` is `null`, all guards no-op, `getAccessToken`
 *    returns `null`, the API client sends no Authorization header.
 *    The backend's disabled-mode (RFC §16) accepts the request.  No
 *    OIDC code path runs.
 *
 * 2. **Enabled** — wraps an `oidc-client-ts` `UserManager`.  On mount,
 *    tries `getUser()` → if a stored session exists we're logged in;
 *    otherwise the consumer (typically `AuthGate`) calls `signIn()` to
 *    redirect to the IdP.  Listens for `userLoaded` / `userUnloaded` /
 *    `silentRenewError` events and re-renders.  Registers an access-
 *    token getter with `lib/auth-token.ts` so the API client picks up
 *    fresh tokens after silent refresh.
 *
 * Roles come from the configured role claim on the access token.  The
 * frontend doesn't enforce role gates server-side — the backend does
 * the authoritative check in `darla.auth.middleware.require_role`.
 * Frontend role-gating only hides UI affordances the user can't use,
 * which is a UX nicety, not a security boundary.
 */

import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { User, UserManager } from "oidc-client-ts";
import { buildUserManagerSettings, readOidcEnv } from "./oidcConfig";
import { setAccessTokenGetter } from "@/lib/auth-token";

export type Role = "viewer" | "analyst";

export interface AuthUser {
  /** Stable subject identifier from the configured subject claim. */
  subject: string;
  /** Display name (token's `name` claim, falls back to UPN/subject). */
  displayName: string;
  /** UPN / preferred_username — typically email-shaped. */
  upn: string;
  /** Effective role derived from the token's role claim. */
  role: Role | null;
}

export interface AuthContextValue {
  /** Build-time mode flag.  Stable for the life of the app. */
  authEnabled: boolean;

  /** True while the provider is determining initial state. */
  loading: boolean;

  /** Authenticated user, or `null` when not signed in / disabled mode. */
  user: AuthUser | null;

  /** Trigger a redirect-to-IdP sign-in.  No-op in disabled mode. */
  signIn: () => Promise<void>;

  /** Sign out locally and (when supported) at the IdP. */
  signOut: () => Promise<void>;

  /** Returns the current access token, or null. */
  getAccessToken: () => string | null;

  /** Last sign-in / silent-renew error, if any.  Used by AuthGate. */
  error: Error | null;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

/** Wire the OIDC role claim into our two-tier role enum. */
function pickRole(roles: string[] | undefined): Role | null {
  if (!roles || roles.length === 0) return null;
  // Mirror the backend's higher-tier-wins semantics
  // (darla.auth.middleware._map_role).  Frontend role-gating must
  // match what the backend will allow, otherwise we'd hide buttons
  // the user could actually use.
  if (roles.includes("Darla.Analyst")) return "analyst";
  if (roles.includes("Darla.Viewer")) return "viewer";
  return null;
}

/** Convert an `oidc-client-ts` `User` into our flatter shape. */
function toAuthUser(user: User): AuthUser {
  // Access-token claims, not id-token claims — Entra's role claim
  // ships in the access token (id-token's `roles` is informational
  // for the SPA, not authoritative).
  // oidc-client-ts decodes both into `user.profile`; the role claim
  // is reachable directly there for any compliant provider.
  const profile = user.profile as Record<string, unknown>;
  const subject = String(profile.sub ?? profile.oid ?? "");
  const displayName = String(profile.name ?? profile.preferred_username ?? subject);
  const upn = String(profile.preferred_username ?? profile.upn ?? "");
  const rawRoles = profile.roles;
  const roles = Array.isArray(rawRoles) ? rawRoles.map(String) : [];
  return { subject, displayName, upn, role: pickRole(roles) };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const env = useMemo(() => readOidcEnv(), []);
  const userManagerRef = useRef<UserManager | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(env.enabled);
  const [error, setError] = useState<Error | null>(null);
  // Hold the live oidc-client User so getAccessToken can read fresh
  // tokens after silent renew.  Refs (not state) because we don't
  // want React re-renders on every silent-refresh tick.
  const oidcUserRef = useRef<User | null>(null);

  // ── Disabled-mode short circuit ──────────────────────────────────
  // No effects, no UserManager construction, nothing.
  // Memoised value below renders an inert provider.

  // ── Enabled-mode setup ───────────────────────────────────────────
  useEffect(() => {
    if (!env.enabled) return;

    const um = new UserManager(buildUserManagerSettings(env));
    userManagerRef.current = um;

    // Register the token getter with the API client BEFORE doing
    // anything async — first-render API calls (e.g. health) need to
    // see the registered getter even if it returns null briefly.
    setAccessTokenGetter(() => oidcUserRef.current?.access_token ?? null);

    // Subscribe to the events oidc-client emits across the session
    // lifecycle.  Storage events fire when a SECOND tab signs in/out
    // — we react so multi-tab UX is consistent.
    const onLoaded = (loaded: User) => {
      oidcUserRef.current = loaded;
      setUser(toAuthUser(loaded));
      setError(null);
    };
    const onUnloaded = () => {
      oidcUserRef.current = null;
      setUser(null);
    };
    const onSilentError = (e: Error) => {
      // Silent refresh failed — token will eventually expire and
      // requests will start 401-ing.  Surface it to AuthGate which
      // triggers a fresh sign-in redirect.
      // eslint-disable-next-line no-console
      console.warn("[auth] silent renew failed:", e);
      setError(e);
    };

    um.events.addUserLoaded(onLoaded);
    um.events.addUserUnloaded(onUnloaded);
    um.events.addSilentRenewError(onSilentError);

    // On mount: do we already have a stored session?  This handles
    // the page-reload case — no need to redirect through the IdP
    // again if we have a still-valid refresh token.
    void um
      .getUser()
      .then((stored) => {
        if (stored && !stored.expired) {
          oidcUserRef.current = stored;
          setUser(toAuthUser(stored));
        }
      })
      .catch((e) => {
        // eslint-disable-next-line no-console
        console.warn("[auth] getUser() failed:", e);
        setError(e instanceof Error ? e : new Error(String(e)));
      })
      .finally(() => setLoading(false));

    return () => {
      um.events.removeUserLoaded(onLoaded);
      um.events.removeUserUnloaded(onUnloaded);
      um.events.removeSilentRenewError(onSilentError);
    };
  }, [env]);

  const signIn = useCallback(async () => {
    if (!env.enabled || !userManagerRef.current) return;
    // Stash the path the user was trying to reach so the post-signin
    // redirect drops them where they expected to be.  Excluded paths:
    // /auth/callback (would loop) and /unauthorized (no role assigned —
    // signing in again won't help).
    const here = window.location.pathname + window.location.search;
    const safe =
      here.startsWith("/auth/") || here.startsWith("/unauthorized") ? "/" : here;
    await userManagerRef.current.signinRedirect({ state: { return_to: safe } });
  }, [env.enabled]);

  const signOut = useCallback(async () => {
    if (!env.enabled || !userManagerRef.current) return;
    try {
      // signoutRedirect hits the IdP's end_session endpoint; if the
      // IdP doesn't support it (older Entra deployments), oidc-client
      // throws — fall back to local-only removal.
      await userManagerRef.current.signoutRedirect();
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn("[auth] IdP signout failed, removing local session:", e);
      await userManagerRef.current.removeUser();
      setUser(null);
      window.location.href = "/";
    }
  }, [env.enabled]);

  const getAccessToken = useCallback(
    (): string | null => oidcUserRef.current?.access_token ?? null,
    [],
  );

  const value: AuthContextValue = useMemo(
    () => ({
      authEnabled: env.enabled,
      loading,
      user,
      signIn,
      signOut,
      getAccessToken,
      error,
    }),
    [env.enabled, loading, user, signIn, signOut, getAccessToken, error],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Internal helper — also exported for the Callback page. */
export function getUserManager(): UserManager | null {
  // The Callback page renders OUTSIDE the AuthProvider's controlled
  // routes (it's a sibling) so it constructs its own UserManager
  // from the env.  This export exists for completeness / debugging.
  return null;
}
