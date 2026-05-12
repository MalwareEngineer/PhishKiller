/**
 * AuthGate — wraps the Shell content and turns the auth state into
 * the right user-visible behaviour.
 *
 *   disabled mode  → render children (no auth flow)
 *   loading        → spinner ("Signing in…")
 *   not signed in  → trigger signinRedirect, show spinner while we go
 *   signed in, no role assigned → redirect to /unauthorized
 *   signed in, role assigned    → render children
 *
 * Lives one level inside `<AuthProvider>` so it can read `useAuth()`
 * and trigger sign-in as soon as the provider says we're not loading.
 */

import { useEffect } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "./useAuth";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { authEnabled, loading, user, signIn } = useAuth();

  // Once the provider has settled (loading=false) and we're enabled
  // but have no user, kick off the sign-in redirect.  Doing this in
  // a useEffect (not during render) keeps the redirect side effect
  // out of the render path, which React strict-mode would otherwise
  // double-invoke.
  useEffect(() => {
    if (authEnabled && !loading && !user) {
      void signIn();
    }
  }, [authEnabled, loading, user, signIn]);

  // Disabled mode is the trivial passthrough — no spinner, no
  // auth check, just render.  This keeps the community quickstart
  // experience identical to the pre-auth state of the codebase.
  if (!authEnabled) return <>{children}</>;

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-sm text-muted-foreground">Signing in…</p>
      </div>
    );
  }

  // Authenticated but the IdP didn't grant Darla.Viewer or
  // Darla.Analyst — surface the cause.  The user has to ask their
  // IT team to add them to a Darla group; signing out and back in
  // won't help.
  if (user.role === null) {
    return <Navigate to="/unauthorized" replace />;
  }

  return <>{children}</>;
}
