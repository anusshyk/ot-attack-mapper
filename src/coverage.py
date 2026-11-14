"""Coverage engine: map controls to ATT&CK for ICS and compute gaps.

Loads the technique matrix and the control inventory, then answers:
  - which techniques are covered by at least one control (and how)
  - which are uncovered (the gaps)
  - coverage percentage per tactic and overall
  - a D3FEND countermeasure summary
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]


@dataclass
class Tactic:
    id: str
    name: str
    short: str


@dataclass
class Control:
    id: str
    name: str
    type: str
    status: str
    covers: list[str]
    d3fend: list[dict]
    source: str = ""


@dataclass
class TechniqueCoverage:
    technique: Technique
    controls: list[Control] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return any(c.status == "deployed" for c in self.controls)

    @property
    def partial(self) -> bool:
        return not self.covered and bool(self.controls)

    @property
    def state(self) -> str:
        if self.covered:
            return "covered"
        if self.partial:
            return "partial"
        return "gap"


class CoverageModel:
    def __init__(self, attack_path: str | Path, controls_path: str | Path):
        attack = json.loads(Path(attack_path).read_text(encoding="utf-8"))
        controls = json.loads(Path(controls_path).read_text(encoding="utf-8"))

        self.dataset_version: str = attack.get("dataset_version", "unknown")
        self.tactics: list[Tactic] = [Tactic(**t) for t in attack["tactics"]]
        self.techniques: dict[str, Technique] = {
            t["id"]: Technique(id=t["id"], name=t["name"], tactics=t["tactics"])
            for t in attack["techniques"]
        }
        self.controls: list[Control] = [
            Control(
                id=c["id"], name=c["name"], type=c.get("type", ""),
                status=c.get("status", "deployed"), covers=c.get("covers", []),
                d3fend=c.get("d3fend", []), source=c.get("source", ""),
            )
            for c in controls["controls"]
        ]

        # Build per-technique coverage, warning on unknown technique ids.
        self.coverage: dict[str, TechniqueCoverage] = {
            tid: TechniqueCoverage(technique=t) for tid, t in self.techniques.items()
        }
        self.unknown_refs: set[str] = set()
        for control in self.controls:
            for tid in control.covers:
                if tid in self.coverage:
                    self.coverage[tid].controls.append(control)
                else:
                    self.unknown_refs.add(tid)

    # ----- summaries -------------------------------------------------------

    def overall(self) -> dict:
        total = len(self.techniques)
        covered = sum(1 for c in self.coverage.values() if c.covered)
        partial = sum(1 for c in self.coverage.values() if c.partial)
        return {
            "total": total,
            "covered": covered,
            "partial": partial,
            "gaps": total - covered - partial,
            "coverage_pct": round(100 * covered / total, 1) if total else 0.0,
        }

    def by_tactic(self) -> list[dict]:
        rows = []
        for tactic in self.tactics:
            techs = [c for c in self.coverage.values() if tactic.id in c.technique.tactics]
            total = len(techs)
            covered = sum(1 for c in techs if c.covered)
            partial = sum(1 for c in techs if c.partial)
            rows.append({
                "tactic": tactic.name,
                "tactic_id": tactic.id,
                "total": total,
                "covered": covered,
                "partial": partial,
                "gaps": total - covered - partial,
                "coverage_pct": round(100 * covered / total, 1) if total else 0.0,
            })
        return rows

    def gaps(self) -> list[Technique]:
        """Techniques with no deployed or partial control."""
        return sorted(
            (c.technique for c in self.coverage.values() if c.state == "gap"),
            key=lambda t: t.id,
        )

    def d3fend_summary(self) -> list[dict]:
        counts: dict[str, dict] = {}
        for control in self.controls:
            for cm in control.d3fend:
                entry = counts.setdefault(cm["id"], {"id": cm["id"], "name": cm["name"], "controls": 0})
                entry["controls"] += 1
        return sorted(counts.values(), key=lambda d: (-d["controls"], d["id"]))
