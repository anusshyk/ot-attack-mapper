#!/usr/bin/env python3
"""ot-attack-mapper: map OT defensive controls to MITRE ATT&CK for ICS + D3FEND.

Commands:
    coverage   print the coverage summary (overall + per tactic)
    gaps       list uncovered techniques
    report     write the HTML heatmap and Markdown gap report
    import-stix  convert an official MITRE ATT&CK for ICS STIX bundle into
                 this tool's attack_ics.json format

Examples:
    python src/main.py coverage
    python src/main.py gaps
    python src/main.py report -o output/
    python src/main.py import-stix ics-attack.json -o data/attack_ics.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from coverage import CoverageModel
import report

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACK = ROOT / "data" / "attack_ics.json"
DEFAULT_CONTROLS = ROOT / "data" / "controls.json"


def cmd_coverage(model: CoverageModel) -> None:
    o = model.overall()
    print(f"ATT&CK for ICS coverage  (dataset {model.dataset_version})")
    print(f"  overall: {o['coverage_pct']}%  "
          f"({o['covered']} covered, {o['partial']} partial, {o['gaps']} gaps / {o['total']})\n")
    print(f"  {'TACTIC':<28} {'COVERED':>9} {'%':>7}")
    for row in model.by_tactic():
        print(f"  {row['tactic']:<28} {row['covered']:>3}/{row['total']:<4} {row['coverage_pct']:>6}%")
    if model.unknown_refs:
        print(f"\n  [!] controls reference {len(model.unknown_refs)} unknown technique id(s): "
              f"{', '.join(sorted(model.unknown_refs))}")


def cmd_gaps(model: CoverageModel) -> None:
    gaps = model.gaps()
    tactic_names = {t.id: t.name for t in model.tactics}
    print(f"{len(gaps)} uncovered technique(s):\n")
    for t in gaps:
        tnames = ", ".join(tactic_names.get(x, x) for x in t.tactics)
        print(f"  {t.id:<7} {t.name:<42} [{tnames}]")


def cmd_report(model: CoverageModel, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "coverage.html"
    md_path = out / "gap_analysis.md"
    html_path.write_text(report.render_html(model), encoding="utf-8")
    md_path.write_text(report.render_markdown_gaps(model), encoding="utf-8")
    o = model.overall()
    print(f"[+] wrote {html_path}")
    print(f"[+] wrote {md_path}")
    print(f"[+] overall coverage: {o['coverage_pct']}%  ({o['covered']}/{o['total']} techniques)")


def cmd_import_stix(stix_path: str, out_path: str) -> None:
    """Convert an official ATT&CK for ICS STIX 2.1 bundle to attack_ics.json."""
    bundle = json.loads(Path(stix_path).read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    tactic_by_short: dict[str, dict] = {}
    techniques: list[dict] = []
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            ref = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), {})
            tactic_by_short[obj.get("x_mitre_shortname", "")] = {
                "id": ref.get("external_id", ""),
                "name": obj.get("name", ""),
                "short": obj.get("x_mitre_shortname", ""),
            }
        elif obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            ref = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), {})
            tid = ref.get("external_id", "")
            if not tid:
                continue
            phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])]
            techniques.append({"id": tid, "name": obj.get("name", ""), "_phases": phases})

    tactics = list(tactic_by_short.values())
    short_to_id = {t["short"]: t["id"] for t in tactics}
    for t in techniques:
        t["tactics"] = [short_to_id[p] for p in t.pop("_phases") if p in short_to_id]

    output = {
        "dataset_version": "official-stix-import",
        "note": "Imported from an official MITRE ATT&CK for ICS STIX bundle.",
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "tactics": tactics,
        "techniques": sorted(techniques, key=lambda t: t["id"]),
    }
    Path(out_path).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[+] imported {len(tactics)} tactics and {len(techniques)} techniques -> {out_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ot-attack-mapper",
        description="Map OT defensive controls to MITRE ATT&CK for ICS and D3FEND.",
    )
    p.add_argument("--attack", default=str(DEFAULT_ATTACK), help="path to attack_ics.json")
    p.add_argument("--controls", default=str(DEFAULT_CONTROLS), help="path to controls.json")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("coverage", help="print coverage summary")
    sub.add_parser("gaps", help="list uncovered techniques")
    rep = sub.add_parser("report", help="write HTML heatmap + Markdown gaps")
    rep.add_argument("-o", "--out", default="output", help="output directory")
    imp = sub.add_parser("import-stix", help="convert official MITRE STIX bundle")
    imp.add_argument("stix", help="path to the ICS ATT&CK STIX json bundle")
    imp.add_argument("-o", "--out", default=str(DEFAULT_ATTACK), help="output attack_ics.json path")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # tolerate | head, etc.
    except (ImportError, AttributeError, ValueError):
        pass  # not available on Windows
    try:
        if args.command == "import-stix":
            cmd_import_stix(args.stix, args.out)
            return
        model = CoverageModel(args.attack, args.controls)
        if args.command == "coverage":
            cmd_coverage(model)
        elif args.command == "gaps":
            cmd_gaps(model)
        elif args.command == "report":
            cmd_report(model, args.out)
    except FileNotFoundError as exc:
        sys.exit(f"[!] file not found: {exc.filename}")


if __name__ == "__main__":
    main()
