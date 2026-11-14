"""Tests for the coverage engine and reports, plus dataset integrity checks."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from coverage import CoverageModel
import report

ROOT = Path(__file__).resolve().parent.parent
ATTACK = ROOT / "data" / "attack_ics.json"
CONTROLS = ROOT / "data" / "controls.json"


class DatasetIntegrityTests(unittest.TestCase):
    """The bundled data must be internally consistent."""

    def setUp(self):
        self.attack = json.loads(ATTACK.read_text())
        self.controls = json.loads(CONTROLS.read_text())

    def test_technique_ids_unique(self):
        ids = [t["id"] for t in self.attack["techniques"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_technique_references_valid_tactic(self):
        tactic_ids = {t["id"] for t in self.attack["tactics"]}
        for tech in self.attack["techniques"]:
            for tac in tech["tactics"]:
                self.assertIn(tac, tactic_ids, f"{tech['id']} references unknown tactic {tac}")

    def test_technique_id_format(self):
        for tech in self.attack["techniques"]:
            self.assertRegex(tech["id"], r"^T\d{4}(\.\d{3})?$")

    def test_controls_reference_known_techniques(self):
        known = {t["id"] for t in self.attack["techniques"]}
        for control in self.controls["controls"]:
            for tid in control["covers"]:
                self.assertIn(tid, known, f"control {control['id']} references unknown {tid}")


class CoverageMathTests(unittest.TestCase):
    def setUp(self):
        self.model = CoverageModel(ATTACK, CONTROLS)

    def test_overall_adds_up(self):
        o = self.model.overall()
        self.assertEqual(o["covered"] + o["partial"] + o["gaps"], o["total"])

    def test_coverage_pct_bounds(self):
        self.assertGreaterEqual(self.model.overall()["coverage_pct"], 0.0)
        self.assertLessEqual(self.model.overall()["coverage_pct"], 100.0)

    def test_no_unknown_refs_in_bundled_data(self):
        self.assertEqual(self.model.unknown_refs, set())

    def test_deployed_control_marks_technique_covered(self):
        # DET-MG-002 (deployed) covers T0836 Modify Parameter.
        self.assertEqual(self.model.coverage["T0836"].state, "covered")

    def test_partial_only_control_is_partial(self):
        # BACKUP-PLC is 'partial' and covers T0873 with no deployed control.
        self.assertEqual(self.model.coverage["T0873"].state, "partial")

    def test_uncovered_technique_is_gap(self):
        # T0879 Damage to Property has no control in the seed data.
        self.assertEqual(self.model.coverage["T0879"].state, "gap")

    def test_by_tactic_totals_match_matrix(self):
        counts = {r["tactic"]: r["total"] for r in self.model.by_tactic()}
        # Matches the official ATT&CK for ICS matrix (v20.1) technique counts.
        self.assertEqual(counts["Discovery"], 8)
        self.assertEqual(counts["Command and Control"], 5)
        self.assertEqual(counts["Impact"], 12)
        self.assertEqual(counts["Privilege Escalation"], 2)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.model = CoverageModel(ATTACK, CONTROLS)

    def test_html_contains_matrix_and_kpis(self):
        out = report.render_html(self.model)
        self.assertIn("Overall coverage", out)
        self.assertIn("T0836", out)
        self.assertTrue(out.strip().startswith("<!doctype html>"))

    def test_markdown_lists_gaps(self):
        out = report.render_markdown_gaps(self.model)
        self.assertIn("Gap Analysis", out)
        self.assertIn("Uncovered techniques", out)


class StixImportTests(unittest.TestCase):
    def test_import_stix_minimal_bundle(self):
        import main
        bundle = {
            "objects": [
                {"type": "x-mitre-tactic", "name": "Impact",
                 "x_mitre_shortname": "impact",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "TA0105"}]},
                {"type": "attack-pattern", "name": "Loss of Safety",
                 "kill_chain_phases": [{"phase_name": "impact"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T0880"}]},
                {"type": "attack-pattern", "name": "Deprecated", "x_mitre_deprecated": True,
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
            ]
        }
        with tempfile.TemporaryDirectory() as d:
            stix = Path(d) / "stix.json"
            out = Path(d) / "attack.json"
            stix.write_text(json.dumps(bundle))
            main.cmd_import_stix(str(stix), str(out))
            result = json.loads(out.read_text())
        ids = [t["id"] for t in result["techniques"]]
        self.assertIn("T0880", ids)
        self.assertNotIn("T9999", ids)  # deprecated dropped
        self.assertEqual(result["techniques"][0]["tactics"], ["TA0105"])


if __name__ == "__main__":
    unittest.main()
