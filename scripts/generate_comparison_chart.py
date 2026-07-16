"""Generate docs/model_comparison.svg: a DOS-themed grid of per-category DVGA detection rate for the
benchmarked models. Each cell is a five-segment gauge; the filled segments are the number of runs
(out of five, at a 30-step budget) in which that model detected the category. Run with
`python scripts/generate_comparison_chart.py`. No dependencies.

qwen figures are the documented benchmark; glm and gpt-oss figures are from the five-run sets in this
repo's results.
"""
from __future__ import annotations

import pathlib

GOLD = "#e8a317"
GOLD_HI = "#ffcf5c"
BG = "#100e0a"
TEXT = "#ece0c8"
MUTED = "#8a7a5c"
EMPTY_F = "#1c160e"   # empty segment fill
EMPTY_S = "#4a3c22"   # empty segment outline
SEP = "#2a2213"       # column separator
FONT = "'Segoe UI', system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif"

# name, mean findings/run, mean tokens/run
MODELS = [("qwen 3.7-max", "6.0", "236k"), ("glm-5.2", "7.4", "242k"), ("gpt-oss-120b", "4.8", "232k")]
# category, [qwen, glm, gpt-oss] detections out of 5; hardest (most discriminating) first
CATS = [
    ("OS COMMAND INJECTION", [1, 5, 1]),
    ("BROKEN ACCESS (BOLA/BFLA)", [3, 5, 2]),
    ("BLIND SSRF (OOB)", [4, 5, 1]),
    ("SQL INJECTION", [1, 1, 0]),
    ("JWT / AUTH BYPASS", [0, 1, 0]),
    ("STACK-TRACE LEAK", [5, 3, 5]),
    ("BATCH-QUERY DOS", [5, 5, 5]),
    ("INTROSPECTION", [5, 5, 5]),
]

W = 726
LABEL_R = 238
PAD_R = 22
PAD_T = 100
PAD_B = 40
ROW_H = 36
SQ = 17
GAP = 4
N = 5
COL_W = (W - LABEL_R - PAD_R) / len(MODELS)
GAUGE_W = N * SQ + (N - 1) * GAP
H = PAD_T + len(CATS) * ROW_H + PAD_B


def col_x(m: int) -> float:
    return LABEL_R + m * COL_W


def gauge_x(m: int) -> float:
    return col_x(m) + (COL_W - GAUGE_W - 26) / 2


def main() -> None:
    s: list[str] = []
    s.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="{FONT}">')
    s.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    s.append(f'<rect x="6" y="6" width="{W - 12}" height="{H - 12}" fill="none" stroke="{GOLD}" stroke-width="2"/>')
    s.append(f'<rect x="11" y="11" width="{W - 22}" height="{H - 22}" fill="none" stroke="{GOLD}" stroke-width="1"/>')
    grid_bottom = PAD_T + len(CATS) * ROW_H
    # column headers: model name, mean findings/run, mean tokens/run
    for m, (name, mean, tok) in enumerate(MODELS):
        cx = col_x(m) + COL_W / 2
        s.append(f'<text x="{cx:.0f}" y="46" fill="{TEXT}" font-size="14.5" font-weight="700" '
                 f'text-anchor="middle">{name}</text>')
        s.append(f'<text x="{cx:.0f}" y="67" fill="{GOLD}" font-size="12.5" font-weight="600" '
                 f'text-anchor="middle">{mean} findings / run</text>')
        s.append(f'<text x="{cx:.0f}" y="84" fill="{MUTED}" font-size="11.5" text-anchor="middle">'
                 f'{tok} tokens / run</text>')
    # column separators
    for m in range(1, len(MODELS)):
        lx = col_x(m)
        s.append(f'<line x1="{lx:.0f}" y1="{PAD_T - 8:.0f}" x2="{lx:.0f}" y2="{grid_bottom:.0f}" '
                 f'stroke="{SEP}" stroke-width="1"/>')
    # rows
    for r, (cat, vals) in enumerate(CATS):
        cy = PAD_T + r * ROW_H + ROW_H / 2
        s.append(f'<text x="{LABEL_R - 16:.0f}" y="{cy + 4:.0f}" fill="{TEXT}" font-size="12" '
                 f'text-anchor="end">{cat}</text>')
        for m, v in enumerate(vals):
            gx = gauge_x(m)
            sqy = cy - SQ / 2
            for i in range(N):
                fx = gx + i * (SQ + GAP)
                if i < v:
                    s.append(f'<rect x="{fx:.0f}" y="{sqy:.0f}" width="{SQ}" height="{SQ}" '
                             f'fill="{GOLD}" stroke="{BG}" stroke-width="1"/>')
                else:
                    s.append(f'<rect x="{fx:.0f}" y="{sqy:.0f}" width="{SQ}" height="{SQ}" '
                             f'fill="{EMPTY_F}" stroke="{EMPTY_S}" stroke-width="1"/>')
            s.append(f'<text x="{gx + GAUGE_W + 8:.0f}" y="{cy + 4:.0f}" '
                     f'fill="{GOLD_HI if v else MUTED}" font-size="12">{v}</text>')
    s.append("</svg>")
    out = pathlib.Path(__file__).resolve().parent.parent / "docs" / "model_comparison.svg"
    out.write_text("\n".join(s), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
