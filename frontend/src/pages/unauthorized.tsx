/**
 * Shown when a successful OIDC sign-in returns a token without one
 * of the Darla app roles (`Darla.Viewer` / `Darla.Analyst`).
 *
 * Per RFC §3 decision #6, the backend rejects role-less tokens with
 * 403 — this page just gives the user actionable language about
 * what to do next.  Signing out and back in won't help (the token
 * shape is determined by IdP-side group assignment), so the action
 * is "ask your IT team."
 */

import { useAuth } from "@/auth/useAuth";

export function UnauthorizedPage() {
  const { user, signOut } = useAuth();

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="max-w-md rounded-lg border border-border bg-card p-6">
        <h1 className="text-lg font-semibold">Access not yet granted</h1>
        <p className="mt-3 text-sm text-muted-foreground">
          You signed in successfully{user?.upn ? <> as <strong>{user.upn}</strong></> : null},
          but your account hasn't been assigned a Darla role yet. Ask your IT
          administrator to add you to either the <code>Darla.Viewer</code> or{" "}
          <code>Darla.Analyst</code> group, then sign in again.
        </p>
        <button
          type="button"
          onClick={() => void signOut()}
          className="mt-5 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Sign out
        </button>
      </div>
    </div>
  );
}
