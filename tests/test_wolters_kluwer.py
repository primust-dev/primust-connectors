"""
UpToDateConnector — comprehensive tests.

Tests:
  - Drug interaction check (severity levels, threshold logic)
  - Dosing range check (within/outside range, renal adjustment)
  - Privacy invariants (no medication names in commitment)
  - Mathematical proof for dosing stages
  - Manifest structure
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.wolters_kluwer import (
    UpToDateConnector,
    PrimustClinicalRecord,
    MANIFEST_DRUG_INTERACTION,
    MANIFEST_DOSING_RANGE_CHECK,
    MANIFEST_CLINICAL_GUIDELINE_ADHERENCE,
    FIT_VALIDATION,
)


def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    return r


def _make_connector(**kw):
    return UpToDateConnector(
        utd_api_key=kw.get("utd_api_key", "utd_test_key"),
        primust_api_key=kw.get("primust_api_key", "pk_test_123"),
        interaction_alert_threshold=kw.get("threshold", "major"),
    )


UTD_NO_INTERACTION = {"interactions": []}

UTD_MAJOR_INTERACTION = {
    "interactions": [
        {"severity": "major", "drug1": "warfarin", "drug2": "aspirin"},
    ]
}

UTD_MODERATE_INTERACTION = {
    "interactions": [
        {"severity": "moderate", "drug1": "lisinopril", "drug2": "potassium"},
    ]
}

UTD_CONTRAINDICATED = {
    "interactions": [
        {
            "severity": "contraindicated",
            "drug1": "methotrexate",
            "drug2": "trimethoprim",
        },
    ]
}

UTD_DOSING_IN_RANGE = {
    "dosing": {
        "min_dose_mg_per_kg": 5.0,
        "max_dose_mg_per_kg": 15.0,
    }
}

UTD_DOSING_RENAL = {
    "dosing": {
        "min_dose_mg_per_kg": 5.0,
        "max_dose_mg_per_kg": 15.0,
        "renal_adjusted_max_mg": 500.0,
    }
}


class TestUpToDateInit:
    def test_default_threshold(self):
        c = _make_connector()
        assert c.interaction_alert_threshold == "major"

    def test_custom_threshold(self):
        c = _make_connector(threshold="moderate")
        assert c.interaction_alert_threshold == "moderate"

    def test_severity_rank_map(self):
        c = _make_connector()
        assert c._severity_rank["contraindicated"] > c._severity_rank["major"]
        assert c._severity_rank["major"] > c._severity_rank["moderate"]
        assert c._severity_rank["moderate"] > c._severity_rank["minor"]
        assert c._severity_rank["minor"] > c._severity_rank["none"]


class TestManifests:
    def test_interaction_manifest_has_2_stages(self):
        assert len(MANIFEST_DRUG_INTERACTION["stages"]) == 2

    def test_dosing_manifest_has_3_stages(self):
        assert len(MANIFEST_DOSING_RANGE_CHECK["stages"]) == 3

    def test_dosing_stages_are_mathematical(self):
        """Dosing range stages hit Mathematical ceiling — arithmetic thresholds."""
        for stage in MANIFEST_DOSING_RANGE_CHECK["stages"]:
            assert stage["proof_level"] == "mathematical"

    def test_dosing_aggregation_all_must_pass(self):
        assert MANIFEST_DOSING_RANGE_CHECK["aggregation"]["method"] == "all_must_pass"

    def test_guideline_manifest_has_2_stages(self):
        assert len(MANIFEST_CLINICAL_GUIDELINE_ADHERENCE["stages"]) == 2

    @patch("primust_connectors.wolters_kluwer.primust")
    def test_register_3_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 3
        assert len(c._manifest_ids) == 3


class TestDrugInteraction:
    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_no_interaction_passes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_NO_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        result = c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="amoxicillin",
            current_medications=["lisinopril"],
            patient_id="pt_001",
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_major_interaction_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_MAJOR_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(threshold="major")
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["aspirin"],
            patient_id="pt_002",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_moderate_below_major_threshold_passes(self, mock_client_cls):
        """Moderate interaction with threshold=major → pass."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_MODERATE_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(threshold="major")
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="lisinopril",
            current_medications=["potassium"],
            patient_id="pt_003",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_moderate_with_moderate_threshold_fails(self, mock_client_cls):
        """Moderate interaction with threshold=moderate → fail."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_MODERATE_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(threshold="moderate")
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="x",
            current_medications=["y"],
            patient_id="pt_004",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_input_commitment_no_medication_names(self, mock_client_cls):
        """Medication names are PHI — only patient_id + drug + count in commitment."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_NO_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["aspirin", "ibuprofen", "metformin"],
            patient_id="pt_005",
        )

        record_call = mock_pipeline.record.call_args
        input_str = record_call.kwargs["input"]
        assert input_str == "pt_005|warfarin|meds_count:3"
        # Medication names must NOT be in the input
        assert "aspirin" not in input_str
        assert "ibuprofen" not in input_str
        assert "metformin" not in input_str

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_default_visibility_opaque(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_NO_INTERACTION
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="x",
            current_medications=["y"],
            patient_id="pt",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"


class TestDosingRange:
    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dose_in_range_passes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_IN_RANGE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        result = c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,  # 500mg for 70kg = 7.14 mg/kg, within 5-15
            weight_kg=70,
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dose_too_high_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_IN_RANGE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=2000,  # 2000/70 = 28.6 mg/kg > 15 max
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dose_too_low_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_IN_RANGE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="drug_x",
            prescribed_dose_mg=100,  # 100/70 = 1.43 mg/kg < 5 min
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_renal_adjustment_applied(self, mock_client_cls):
        """CrCl < 30 triggers renal dose adjustment."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_RENAL
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        # 700mg for 70kg = 10mg/kg (within 5-15 normally)
        # But renal_adjusted_max_mg = 500, so 700 > 500 → fail
        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="drug_renal",
            prescribed_dose_mg=700,
            weight_kg=70,
            crcl=20,  # < 30 triggers renal adjustment
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"
        details = record_call.kwargs["details"]
        assert details["renal_adjusted"] is True

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_visibility_selective(self, mock_client_cls):
        """Dosing defaults to selective — ranges can be shown, patient data opaque."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_IN_RANGE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="x",
            prescribed_dose_mg=500,
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "selective"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_details_include_range_bounds(self, mock_client_cls):
        """Range bounds are published — OK to include in details."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = UTD_DOSING_IN_RANGE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="x",
            prescribed_dose_mg=500,
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "min_dose_mg" in details
        assert "max_dose_mg" in details


class TestParsing:
    def test_parse_no_interactions(self):
        c = _make_connector()
        result = c._parse_interaction_response(UTD_NO_INTERACTION, "drug_a", ["drug_b"])
        assert result.interaction_found is False
        assert result.severity == "none"

    def test_parse_major_interaction(self):
        c = _make_connector()
        result = c._parse_interaction_response(UTD_MAJOR_INTERACTION, "warfarin", ["aspirin"])
        assert result.interaction_found is True
        assert result.severity == "major"

    def test_parse_contraindicated(self):
        c = _make_connector()
        result = c._parse_interaction_response(UTD_CONTRAINDICATED, "a", ["b"])
        assert result.severity == "contraindicated"

    def test_parse_dosing_in_range(self):
        c = _make_connector()
        result = c._parse_dosing_response(UTD_DOSING_IN_RANGE, 500, 70, None)
        assert result.within_range is True
        assert result.min_dose_mg == 350.0  # 5 * 70
        assert result.max_dose_mg == 1050.0  # 15 * 70

    def test_parse_dosing_renal_adjusted(self):
        c = _make_connector()
        result = c._parse_dosing_response(UTD_DOSING_RENAL, 600, 70, 20)
        assert result.renal_adjusted is True
        assert result.max_dose_mg == 500.0  # capped by renal


class TestFitValidation:
    def test_strong_fit(self):
        assert FIT_VALIDATION["fit"] == "STRONG"

    def test_hipaa_paradox_resolved(self):
        assert FIT_VALIDATION["hipaa_paradox_resolved"] is True

    def test_mathematical_dosing_stages(self):
        assert FIT_VALIDATION["proof_ceiling"]["dosing_threshold_stages"] == "mathematical"

    def test_buildable_today(self):
        assert FIT_VALIDATION["buildable_today"] is True
