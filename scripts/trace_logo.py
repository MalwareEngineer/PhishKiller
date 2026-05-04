"""One-off helper: trace darla-logo.png to a clean themeable SVG.

Reads ``frontend/public/darla-logo.png``, crops to the artwork bbox,
binarizes, runs potrace, emits two SVGs:

  - ``frontend/public/favicon.svg``  — uses ``currentColor`` so it
    auto-adapts to whatever foreground color is set by the
    surrounding context (or via ``<link>`` color in modern browsers).

The script is intentionally idempotent — re-run it any time the
source PNG is updated.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import potrace
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "frontend" / "public" / "darla-logo.png"
OUT_SVG = ROOT / "frontend" / "public" / "favicon.svg"

# How aggressive the binarization is.  Hand-drawn ink lines often
# fall off to ~150-200; clamp at 200 so faint scale strokes survive.
BINARIZE_THRESHOLD = 200

# Margin added around the cropped artwork inside the final viewBox.
# 8% padding keeps the bowl from kissing the favicon edge at 16px.
PADDING_PCT = 0.08


def main() -> int:
    # Work directly in numpy from the start.  The original PNG has
    # dark ink (low values) on a white page (255).  ``ink`` is a
    # 2-D bool array — True where the user drew, False elsewhere.
    arr = np.array(Image.open(SRC).convert("L"))
    ink = arr < BINARIZE_THRESHOLD

    if not ink.any():
        print("ERROR: image is entirely white", file=sys.stderr)
        return 1

    # Tight bbox of ink pixels (rows then cols), then pad
    # proportionally + square so the favicon scales without
    # distortion.
    rows = np.where(ink.any(axis=1))[0]
    cols = np.where(ink.any(axis=0))[0]
    y0, y1 = int(rows[0]), int(rows[-1]) + 1
    x0, x1 = int(cols[0]), int(cols[-1]) + 1

    w, h = x1 - x0, y1 - y0
    pad = int(round(max(w, h) * PADDING_PCT))
    y0 = max(0, y0 - pad)
    x0 = max(0, x0 - pad)
    y1 = min(arr.shape[0], y1 + pad)
    x1 = min(arr.shape[1], x1 + pad)

    cropped = ink[y0:y1, x0:x1]
    h, w = cropped.shape
    side = max(h, w)

    # Square canvas with the cropped art centered; padding is False
    # (paper) so it never gets traced.
    canvas = np.zeros((side, side), dtype=bool)
    yo, xo = (side - h) // 2, (side - w) // 2
    canvas[yo:yo + h, xo:xo + w] = cropped

    # Trace.  potrace's ``Bitmap`` with the default ``blacklevel=0.5``
    # treats values above 0.5 as white and traces values below — i.e.
    # it traces the False pixels of a bool array.  We want the ink
    # (True) traced, so invert: pass ``~canvas`` so paper becomes the
    # untraced background and the drawn lines become the foreground.
    bm = potrace.Bitmap(~canvas)
    path = bm.trace(turdsize=2, opttolerance=0.2)

    # Emit SVG with currentColor fill.  Single combined path with
    # nonzero fill rule preserves the inner cutouts (X eye, scales).
    svg_paths: list[str] = []
    for curve in path:
        parts: list[str] = []
        start = curve.start_point
        parts.append(f"M{start.x:.2f} {start.y:.2f}")
        for seg in curve:
            if isinstance(seg, potrace.BezierSegment):
                parts.append(
                    f"C{seg.c1.x:.2f} {seg.c1.y:.2f} "
                    f"{seg.c2.x:.2f} {seg.c2.y:.2f} "
                    f"{seg.end_point.x:.2f} {seg.end_point.y:.2f}"
                )
            else:  # CornerSegment
                parts.append(
                    f"L{seg.c.x:.2f} {seg.c.y:.2f} "
                    f"L{seg.end_point.x:.2f} {seg.end_point.y:.2f}"
                )
        parts.append("Z")
        svg_paths.append(" ".join(parts))

    combined_d = " ".join(svg_paths)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {side} {side}" fill="currentColor" '
        f'fill-rule="evenodd">'
        f'<path d="{combined_d}"/>'
        f'</svg>'
    )

    OUT_SVG.write_text(svg, encoding="utf-8")
    size_kb = len(svg) / 1024
    print(
        f"Wrote {OUT_SVG.relative_to(ROOT)} "
        f"(viewBox={side}x{side}, {size_kb:.1f} KB, "
        f"{len(svg_paths)} subpaths)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
