import { cn } from "@/lib/utils";

/**
 * The Darla brand mark — outlined dead fish in a fishbowl.
 *
 * Renders the favicon SVG via a CSS ``mask-image`` so the silhouette
 * gets painted in whatever the surrounding text color is (via
 * ``bg-current``).  This keeps a single source of truth — the SVG
 * file at ``/favicon.svg`` — and lets the logo inherit the dark
 * theme's foreground colour, the emerald accent, ``muted-foreground``
 * for collapsed sidebar states, etc., without per-theme asset
 * duplication or inlining a ~26 KB blob into the JS bundle.
 */
export function DarlaLogo({ className }: { className?: string }) {
  return (
    <span
      role="img"
      aria-label="Darla"
      className={cn("inline-block bg-current shrink-0", className)}
      style={{
        // `mask-image` paints `bg-current` only where the SVG is
        // opaque; transparent regions punch through.  The favicon
        // SVG uses fill-rule="evenodd" so the inner cutouts (X eye,
        // scale lines, etc.) come through as transparent gaps —
        // works the same way under a mask.
        maskImage: "url(/favicon.svg)",
        maskSize: "contain",
        maskRepeat: "no-repeat",
        maskPosition: "center",
        WebkitMaskImage: "url(/favicon.svg)",
        WebkitMaskSize: "contain",
        WebkitMaskRepeat: "no-repeat",
        WebkitMaskPosition: "center",
      }}
    />
  );
}
