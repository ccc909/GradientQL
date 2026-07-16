"""Generate docs/model_comparison.svg: a DOS-themed bar chart of per-category DVGA detection rate
for the two benchmarked models. Run with `python scripts/generate_comparison_chart.py`. No deps.

Data: five runs per model at a 30-step budget; each value is the number of runs (out of five) in
which that DVGA category was detected. qwen figures are the documented benchmark; glm figures are
from the five-run set in this repo's results.
"""
from __future__ import annotations

import pathlib

GOLD = "#e8a317"
GOLD_HI = "#ffcf5c"
AMBER = "#b9770c"      # qwen bars (dimmer amber)
BG = "#100e0a"
TEXT = "#ece0c8"
MUTED = "#8a7a5c"
GRID = "#332813"

# (category, qwen /5, glm /5), ordered by severity/interest
DATA = [
    ("OS COMMAND INJECTION", 1, 5),
    ("SQL INJECTION", 1, 1),
    ("BROKEN ACCESS (BOLA/BFLA)", 3, 5),
    ("JWT / AUTH BYPASS", 0, 1),
    ("BLIND SSRF (OOB)", 4, 5),
    ("BATCH-QUERY DOS", 5, 5),
    ("STACK-TRACE LEAK", 5, 3),
    ("INTROSPECTION", 5, 5),
]

W = 760
PAD_L, PAD_R, PAD_T, PAD_B = 232, 54, 108, 58
ROW_H, BAR_H, BAR_GAP = 44, 14, 6
MAXV = 5
PLOT_W = W - PAD_L - PAD_R
H = PAD_T + len(DATA) * ROW_H + PAD_B


def x(v: float) -> float:
    return PAD_L + v / MAXV * PLOT_W


def solid_bar(px: float, py: float, w: float, fill: str = GOLD) -> str:
    return f'<rect x="{px:.0f}" y="{py:.0f}" width="{w:.0f}" height="{BAR_H}" fill="{fill}" stroke="{BG}" stroke-width="1"/>'


def outline_bar(px: float, py: float, w: float) -> str:
    # hollow bar for the baseline model, distinct from the solid one at a glance
    return (f'<rect x="{px + 1:.0f}" y="{py + 1:.0f}" width="{max(w - 2, 2):.0f}" height="{BAR_H - 2}" '
            f'fill="none" stroke="{AMBER}" stroke-width="1.6"/>')


def main() -> None:
    s: list[str] = []
    s.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
             f'font-family="ui-monospace, \'Courier New\', monospace">')
    s.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    # double-line DOS frame
    s.append(f'<rect x="6" y="6" width="{W - 12}" height="{H - 12}" fill="none" stroke="{GOLD}" stroke-width="2"/>')
    s.append(f'<rect x="11" y="11" width="{W - 22}" height="{H - 22}" fill="none" stroke="{GOLD}" stroke-width="1"/>')
    # title
    s.append(f'<text x="{W / 2:.0f}" y="40" fill="{GOLD_HI}" font-size="20" font-weight="bold" '
             f'text-anchor="middle" letter-spacing="3">DVGA DETECTION RATE</text>')
    s.append(f'<text x="{W / 2:.0f}" y="61" fill="{MUTED}" font-size="11.5" text-anchor="middle" '
             f'letter-spacing="1.5">5 RUNS @ BUDGET 30  ::  RUNS (OF 5) IN WHICH EACH CATEGORY WAS FOUND</text>')
    # legend
    s.append(outline_bar(PAD_L, 78, 15))
    s.append(f'<text x="{PAD_L + 23}" y="90" fill="{TEXT}" font-size="12.5">qwen/qwen3.7-max  (6.0/run)</text>')
    s.append(solid_bar(PAD_L + 300, 78, 15))
    s.append(f'<text x="{PAD_L + 323}" y="90" fill="{TEXT}" font-size="12.5">z-ai/glm-5.2  (7.4/run)</text>')
    # gridlines + axis ticks
    axis_bottom = PAD_T + len(DATA) * ROW_H
    for v in range(MAXV + 1):
        gx = x(v)
        s.append(f'<line x1="{gx:.0f}" y1="{PAD_T}" x2="{gx:.0f}" y2="{axis_bottom}" stroke="{GRID}" stroke-width="1"/>')
        s.append(f'<text x="{gx:.0f}" y="{axis_bottom + 19}" fill="{MUTED}" font-size="11" text-anchor="middle">{v}</text>')
    s.append(f'<text x="{(PAD_L + x(MAXV)) / 2:.0f}" y="{axis_bottom + 40}" fill="{MUTED}" font-size="11" '
             f'text-anchor="middle" letter-spacing="1">DETECTIONS (OUT OF 5 RUNS)</text>')
    # rows
    for i, (cat, q, g) in enumerate(DATA):
        ry = PAD_T + i * ROW_H + 6
        s.append(f'<text x="{PAD_L - 14}" y="{ry + BAR_H + 4:.0f}" fill="{TEXT}" font-size="12" '
                 f'text-anchor="end" letter-spacing="0.5">{cat}</text>')
        if q > 0:
            s.append(outline_bar(PAD_L, ry, x(q) - PAD_L))
            s.append(f'<text x="{x(q) + 7:.0f}" y="{ry + BAR_H - 2:.0f}" fill="{MUTED}" font-size="11">{q}</text>')
        gy = ry + BAR_H + BAR_GAP
        if g > 0:
            s.append(solid_bar(PAD_L, gy, x(g) - PAD_L))
            s.append(f'<text x="{x(g) + 7:.0f}" y="{gy + BAR_H - 2:.0f}" fill="{GOLD_HI}" font-size="11">{g}</text>')
    s.append("</svg>")
    out = pathlib.Path(__file__).resolve().parent.parent / "docs" / "model_comparison.svg"
    out.write_text("\n".join(s), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
