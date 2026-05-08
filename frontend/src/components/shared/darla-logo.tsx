import { cn } from "@/lib/utils";

/**
 * Darla brand mark — the textured-orange fiery wordmark + matching
 * D glyph.  Full-colour raster artwork, displayed as ``<img>``: no
 * theming logic, no mask-image tricks, just the artwork as drawn.
 *
 * Use ``variant="full"`` for the wordmark (sidebar expanded, splash,
 * about page) and ``variant="mark"`` for the D-only glyph (sidebar
 * collapsed, favicon-style spots, tight headers).
 */
export function DarlaLogo({
  variant = "full",
  className,
}: {
  variant?: "full" | "mark";
  className?: string;
}) {
  const src = variant === "full" ? "/DARLA.png" : "/D.png";
  // Both source PNGs are exported tight — no transparent margin —
  // so a small inset shadow / glow lives at the exact edge.  Don't
  // add padding here; let the parent decide the size box.
  return (
    <img
      src={src}
      alt="Darla"
      draggable={false}
      className={cn("select-none", className)}
    />
  );
}
