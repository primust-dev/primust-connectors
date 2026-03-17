# Copyright 2026 Primust, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
UpToDateConnector — comprehensive tests.

Tests:
  - Drug interaction check (severity levels, threshold logic)
  - Dosing range check (within/outside range, renal adjustment)
  - Privacy invariants (no patient data in commitment)
  - Mathematical proof for dosing stages
  - Manifest structure & regulatory references
  - Gap codes (API error, auth failure)
  - Commitment format (input_commitment hash dicts)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.wolters_kluwer import (
    UpToDateConnector,
    DrugInteractionResult,
    DosingResult,
    PrimustClinicalRecord,
    MANIFEST_DRUG_INTERACTION,
    MANIFEST_DOSING_RANGE_CHECK,
    MANIFEST_CLINICAL_GUIDELINE_ADHERENCE,
    FIT_VALIDATION,
    _commit,
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
        primust_api_key=kw.get("primust_api_key", "pk_sb_123"),
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
        {"severity": "contraindicated", "drug1": "methotrexate", "drug2": "trimethoprim"},
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


def _setup_mock_client(mock_client_cls, response_data):
    """Helper to set up a mock httpx.Client with a given JSON response."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client


def _setup_mock_client_error(mock_client_cls, status_code):
    """Helper to set up a mock httpx.Client that raises HTTPStatusError."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = "error"
    error = httpx.HTTPStatusError(
        message=f"HTTP {status_code}",
        request=MagicMock(),
        response=mock_response,
    )
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = error
    mock_client.get.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client


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

    def test_all_stages_have_regulatory_references(self):
        """Every stage in every manifest must have regulatory_references."""
        for manifest in [MANIFEST_DRUG_INTERACTION, MANIFEST_DOSING_RANGE_CHECK, MANIFEST_CLINICAL_GUIDELINE_ADHERENCE]:
            for stage in manifest["stages"]:
                assert "regulatory_references" in stage, (
                    f"Stage {stage['name']} in {manifest['name']} missing regulatory_references"
                )
                assert len(stage["regulatory_references"]) > 0

    def test_regulatory_references_contain_expected_tags(self):
        """Regulatory references include the key healthcare tags."""
        all_refs = set()
        for manifest in [MANIFEST_DRUG_INTERACTION, MANIFEST_DOSING_RANGE_CHECK, MANIFEST_CLINICAL_GUIDELINE_ADHERENCE]:
            for stage in manifest["stages"]:
                all_refs.update(stage["regulatory_references"])
        assert "hipaa_phi" in all_refs
        assert "fda_drug_safety" in all_refs
        assert "cms_conditions_participation" in all_refs

    def test_drug_interaction_stages_are_mathematical(self):
        """Drug interaction stages use mathematical ceiling (deterministic lookup)."""
        for stage in MANIFEST_DRUG_INTERACTION["stages"]:
            assert stage["proof_level"] == "mathematical"


class TestCommitmentFormat:
    def test_commit_produces_string(self):
        result = _commit({"key": "value"})
        assert isinstance(result, str)

    def test_commit_deterministic(self):
        """Same input produces same hash."""
        a = _commit({"x": 1, "y": 2})
        b = _commit({"x": 1, "y": 2})
        assert a == b

    def test_commit_sorted_keys(self):
        """Key order does not matter — sort_keys ensures stable hashing."""
        a = _commit({"b": 2, "a": 1})
        b = _commit({"a": 1, "b": 2})
        assert a == b

    def test_commit_different_data_different_hash(self):
        a = _commit({"x": 1})
        b = _commit({"x": 2})
        assert a != b


class TestDrugInteraction:
    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_no_interaction_passes(self, mock_client_cls):
        _setup_mock_client(mock_client_cls, UTD_NO_INTERACTION)

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
        _setup_mock_client(mock_client_cls, UTD_MAJOR_INTERACTION)

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
        """Moderate interaction with threshold=major -> pass."""
        _setup_mock_client(mock_client_cls, UTD_MODERATE_INTERACTION)

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
        """Moderate interaction with threshold=moderate -> fail."""
        _setup_mock_client(mock_client_cls, UTD_MODERATE_INTERACTION)

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
    def test_input_is_commitment_hash_dict(self, mock_client_cls):
        """Input must be a dict with input_commitment key (hash string)."""
        _setup_mock_client(mock_client_cls, UTD_NO_INTERACTION)

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
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert isinstance(input_val["input_commitment"], str)

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_no_patient_data_in_commitment(self, mock_client_cls):
        """Patient ID must NOT appear in the commitment hash input."""
        _setup_mock_client(mock_client_cls, UTD_NO_INTERACTION)

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
        input_val = record_call.kwargs["input"]
        # The commitment is a hash — patient_id should not appear anywhere
        input_str = json.dumps(input_val)
        assert "pt_005" not in input_str

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_drug_ids_sorted_for_stable_ordering(self, mock_client_cls):
        """Drug IDs are sorted before commitment for deterministic hashing."""
        _setup_mock_client(mock_client_cls, UTD_NO_INTERACTION)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        # Call with unsorted list
        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["metformin", "aspirin", "ibuprofen"],
            patient_id="pt_006",
        )
        call1 = mock_pipeline.record.call_args.kwargs["input"]["input_commitment"]

        mock_pipeline.reset_mock()
        mock_pipeline.record.return_value = _mock_record_result()

        # Call with same meds in different order
        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["ibuprofen", "metformin", "aspirin"],
            patient_id="pt_007",
        )
        call2 = mock_pipeline.record.call_args.kwargs["input"]["input_commitment"]

        assert call1 == call2, "Commitment should be stable regardless of medication order"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_default_visibility_opaque(self, mock_client_cls):
        _setup_mock_client(mock_client_cls, UTD_NO_INTERACTION)

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
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        result = c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,   # 500mg for 70kg = 7.14 mg/kg, within 5-15
            weight_kg=70,
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dose_too_high_fails(self, mock_client_cls):
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

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
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="drug_x",
            prescribed_dose_mg=100,   # 100/70 = 1.43 mg/kg < 5 min
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_renal_adjustment_applied(self, mock_client_cls):
        """CrCl < 30 triggers renal dose adjustment."""
        _setup_mock_client(mock_client_cls, UTD_DOSING_RENAL)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        # 700mg for 70kg = 10mg/kg (within 5-15 normally)
        # But renal_adjusted_max_mg = 500, so 700 > 500 -> fail
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
    def test_dosing_visibility_opaque(self, mock_client_cls):
        """Dosing defaults to opaque — patient weight/renal function are PHI."""
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

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
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_details_include_range_bounds(self, mock_client_cls):
        """Range bounds are published — OK to include in details."""
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

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

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_input_is_commitment_hash_dict(self, mock_client_cls):
        """Dosing input must be a dict with input_commitment key."""
        _setup_mock_client(mock_client_cls, UTD_DOSING_IN_RANGE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,
            weight_kg=70,
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert isinstance(input_val["input_commitment"], str)


class TestGapCodes:
    """Gap code handling — fail-open with error recording."""

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_interaction_api_error_records_gap(self, mock_client_cls):
        """Non-401 API error records wolters_kluwer_api_error gap."""
        _setup_mock_client_error(mock_client_cls, 500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        result = c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["aspirin"],
            patient_id="pt_err",
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "wolters_kluwer_api_error"
        assert record_call.kwargs["details"]["severity"] == "high"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_interaction_auth_failure_records_critical_gap(self, mock_client_cls):
        """401 records wolters_kluwer_auth_failure with critical severity."""
        _setup_mock_client_error(mock_client_cls, 401)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        result = c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["aspirin"],
            patient_id="pt_auth",
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "wolters_kluwer_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_api_error_records_gap(self, mock_client_cls):
        """Non-401 dosing API error records gap."""
        _setup_mock_client_error(mock_client_cls, 503)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        result = c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,
            weight_kg=70,
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "wolters_kluwer_api_error"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_dosing_auth_failure_records_critical_gap(self, mock_client_cls):
        """401 on dosing records auth failure with critical severity."""
        _setup_mock_client_error(mock_client_cls, 401)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_dosing_range_check"] = "sha256:test"

        result = c.check_dosing_range(
            pipeline=mock_pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,
            weight_kg=70,
        )

        assert isinstance(result, PrimustClinicalRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "wolters_kluwer_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_gap_records_use_opaque_visibility(self, mock_client_cls):
        """Error records always use opaque visibility."""
        _setup_mock_client_error(mock_client_cls, 500)

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

    @patch("primust_connectors.wolters_kluwer.httpx.Client")
    def test_gap_records_include_input_commitment(self, mock_client_cls):
        """Error records still include the input_commitment hash."""
        _setup_mock_client_error(mock_client_cls, 500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["uptodate_drug_interaction_check"] = "sha256:test"

        c.check_drug_interaction(
            pipeline=mock_pipeline,
            new_drug="warfarin",
            current_medications=["aspirin"],
            patient_id="pt_gap",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val


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
        assert result.min_dose_mg == 350.0   # 5 * 70
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
