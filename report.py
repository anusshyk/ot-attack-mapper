"""Render coverage as an HTML heatmap and a Markdown gap report."""

from __future__ import annotations

import html
from coverage import CoverageModel

STATE_COLOR = {
    "covered": "#1f7a34",   # green
    "partial": "#b7791f",   # amber
    "gap": "#3a1212",       # dark red
}
STATE_BORDER = {
    "covered": "#41c350",
    "partial": "#f0b64a",
    "gap": "#c1444a",
}


def render_html(model: CoverageModel) -> str:
    overall = model.overall()
    tactics = model.tactics

    # Column (per tactic) list of technique coverage cells.
    columns: list[tuple[str, list]] = []
    for tactic in tactics:
        cells = sorted(
            (c for c in model.coverage.values() if tactic.id in c.technique.tactics),
            key=lambda c: c.technique.id,
        )
        columns.append((tactic.name, cells))

    max_rows = max((len(c) for _, c in columns), default=0)

    head_cells = "".join(
        f'<th><div class="tac">{html.escape(name)}</div>'
        f'<div class="cnt">{len(cells)}</div></th>'
        for name, cells in columns
    )

    body_rows = []
    for r in range(max_rows):
        tds = []
        for _, cells in columns:
            if r < len(cells):
                cov = cells[r]
                t = cov.technique
                ctrl = ", ".join(c.id for c in cov.controls) or "no control"
                tip = f"{t.id} {t.name}\\nstate: {cov.state}\\n{ctrl}"
                tds.append(
                    f'<td class="cell {cov.state}" title="{html.escape(tip)}">'
                    f'<span class="tid">{t.id}</span>'
                    f'<span class="tname">{html.escape(t.name)}</span></td>'
                )
            else:
                tds.append('<td class="empty"></td>')
        body_rows.append("<tr>" + "".join(tds) + "</tr>")

    tactic_rows = "".join(
        f'<tr><td>{html.escape(row["tactic"])}</td>'
        f'<td class="num">{row["covered"]}/{row["total"]}</td>'
        f'<td class="num">{row["coverage_pct"]}%</td>'
        f'<td><div class="bar"><div class="fill" style="width:{row["coverage_pct"]}%"></div></div></td></tr>'
        for row in model.by_tactic()
    )

    d3_rows = "".join(
        f'<tr><td class="mono">{html.escape(d["id"])}</td>'
        f'<td>{html.escape(d["name"])}</td>'
        f'<td class="num">{d["controls"]}</td></tr>'
        for d in model.d3fend_summary()
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OT ATT&CK &amp; D3FEND Coverage</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; background:#01102d; color:#e6eef8;
    font-family: 'Segoe UI', system-ui, sans-serif; padding:28px; }}
  h1 {{ margin:0 0 4px; font-size:24px; }}
  h1 span {{ color:#41c350; }}
  .sub {{ color:#8fa6c4; margin-bottom:20px; font-size:14px; }}
  .kpis {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:24px; }}
  .kpi {{ background:#07204a; border:1px solid #163a6b; border-radius:12px;
    padding:14px 20px; min-width:120px; }}
  .kpi .v {{ font-size:28px; font-weight:700; }}
  .kpi .l {{ font-size:12px; color:#8fa6c4; text-transform:uppercase; letter-spacing:.5px; }}
  .legend {{ display:flex; gap:16px; margin-bottom:12px; font-size:13px; align-items:center; }}
  .chip {{ display:inline-block; width:12px; height:12px; border-radius:3px; margin-right:6px; vertical-align:middle; }}
  .matrix-wrap {{ overflow-x:auto; border:1px solid #163a6b; border-radius:12px; }}
  table.matrix {{ border-collapse:collapse; width:100%; }}
  table.matrix th {{ background:#07204a; padding:10px 6px; vertical-align:top;
    border-bottom:2px solid #163a6b; min-width:150px; }}
  table.matrix th .tac {{ font-size:12.5px; }}
  table.matrix th .cnt {{ font-size:11px; color:#8fa6c4; }}
  td.cell {{ border:1px solid #0a1e40; border-left:3px solid; padding:6px 8px;
    vertical-align:top; }}
  td.cell .tid {{ display:block; font-family:ui-monospace, monospace; font-size:11px; color:#cfe0f5; }}
  td.cell .tname {{ display:block; font-size:12px; }}
  td.empty {{ background:#040f24; }}
  td.covered {{ background:{STATE_COLOR['covered']}22; border-left-color:{STATE_BORDER['covered']}; }}
  td.partial {{ background:{STATE_COLOR['partial']}22; border-left-color:{STATE_BORDER['partial']}; }}
  td.gap {{ background:{STATE_COLOR['gap']}; border-left-color:{STATE_BORDER['gap']}; }}
  h2 {{ margin:30px 0 10px; font-size:18px; }}
  table.data {{ border-collapse:collapse; width:100%; max-width:720px; }}
  table.data td, table.data th {{ text-align:left; padding:7px 10px; border-bottom:1px solid #163a6b; font-size:13.5px; }}
  table.data .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .mono {{ font-family:ui-monospace, monospace; }}
  .bar {{ background:#0a1e40; border-radius:6px; height:10px; width:160px; overflow:hidden; }}
  .fill {{ background:#41c350; height:100%; }}
  footer {{ margin-top:28px; color:#6c84a6; font-size:12px; }}
</style></head>
<body>
  <h1>OT <span>ATT&amp;CK</span> &amp; <span>D3FEND</span> Coverage</h1>
  <div class="sub">MITRE ATT&amp;CK for ICS defensive coverage &middot; dataset {html.escape(model.dataset_version)}
    &middot; {len(model.controls)} controls</div>

  <div class="kpis">
    <div class="kpi"><div class="v">{overall['coverage_pct']}%</div><div class="l">Overall coverage</div></div>
    <div class="kpi"><div class="v">{overall['covered']}</div><div class="l">Covered</div></div>
    <div class="kpi"><div class="v">{overall['partial']}</div><div class="l">Partial</div></div>
    <div class="kpi"><div class="v">{overall['gaps']}</div><div class="l">Gaps</div></div>
    <div class="kpi"><div class="v">{overall['total']}</div><div class="l">Techniques</div></div>
  </div>

  <div class="legend">
    <span><span class="chip" style="background:{STATE_BORDER['covered']}"></span>Covered (deployed)</span>
    <span><span class="chip" style="background:{STATE_BORDER['partial']}"></span>Partial / planned</span>
    <span><span class="chip" style="background:{STATE_BORDER['gap']}"></span>Gap (no control)</span>
  </div>

  <div class="matrix-wrap">
    <table class="matrix"><thead><tr>{head_cells}</tr></thead>
    <tbody>{''.join(body_rows)}</tbody></table>
  </div>

  <h2>Coverage by tactic</h2>
  <table class="data"><thead><tr><th>Tactic</th><th class="num">Covered</th>
    <th class="num">%</th><th>Progress</th></tr></thead>
    <tbody>{tactic_rows}</tbody></table>

  <h2>D3FEND countermeasures in use</h2>
  <table class="data"><thead><tr><th>ID</th><th>Countermeasure</th>
    <th class="num">Controls</th></tr></thead>
    <tbody>{d3_rows}</tbody></table>

  <footer>Generated by ot-attack-mapper. Coverage reflects the controls in data/controls.json.
    Validate the technique set against attack.mitre.org before reporting externally.</footer>
</body></html>
"""


def render_markdown_gaps(model: CoverageModel) -> str:
    overall = model.overall()
    lines = [
        "# OT ATT&CK for ICS - Gap Analysis",
        "",
        f"- Dataset: {model.dataset_version}",
        f"- Controls evaluated: {len(model.controls)}",
        f"- Overall coverage: **{overall['coverage_pct']}%** "
        f"({overall['covered']} covered, {overall['partial']} partial, {overall['gaps']} gaps "
        f"of {overall['total']} techniques)",
        "",
        "## Coverage by tactic",
        "",
        "| Tactic | Covered | Partial | Gaps | Coverage |",
        "|---|---|---|---|---|",
    ]
    for row in model.by_tactic():
        lines.append(
            f"| {row['tactic']} | {row['covered']} | {row['partial']} | "
            f"{row['gaps']} | {row['coverage_pct']}% |"
        )
    lines += ["", "## Uncovered techniques (priority gaps)", ""]
    gaps = model.gaps()
    if not gaps:
        lines.append("No gaps - every technique has at least a partial control.")
    else:
        lines.append("| Technique | Name | Tactic(s) |")
        lines.append("|---|---|---|")
        tactic_names = {t.id: t.name for t in model.tactics}
        for t in gaps:
            tnames = ", ".join(tactic_names.get(x, x) for x in t.tactics)
            lines.append(f"| {t.id} | {t.name} | {tnames} |")
    lines += ["", "_Generated by ot-attack-mapper._"]
    return "\n".join(lines)
