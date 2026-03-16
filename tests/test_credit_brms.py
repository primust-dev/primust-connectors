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
FicoBlazeConnector + IBMODMConnector — comprehensive tests.

Tests:
  - Credit decisioning (approve/decline/refer)
  - ODM decision execution
  - Commitment format (sha256: prefix, canonical JSON)
  - Gap code handling (API errors, auth failures)
  - Privacy invariants (no reason codes in details)
  - Framework tags (regulatory_references)
  - Manifest structure
  - BlazeAdvisorJava demand-gate stub
  - Convenience wrappers (execute_credit_decision, execute_aml_screening)
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.credit_brms import (
    FicoBlazeConnector,
    IBMODMConnector,
    BlazeAdvisorJava,
    BlazeDecisionResult,
    PrimustDecisionRecord,
    BLAZE_MANIFEST_CREDIT_DECISIONING,
    ODM_MANIFEST_UNDERWRITING,
    BLAZE_FIT_VALIDATION,
    ODM_FIT_VALIDATION,
    _commit,
)


def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    return r


def _mock_httpx_client(response_data):
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    return mock_client


BLAZE_APPROVE = {
    "decision": "APPROVE",
    "score": 780,
    "rulesFired": ["CREDIT_BAND_1", "DTI_CHECK", "LTV_CHECK"],
    "reasons": [],
}

BLAZE_DECLINE = {
    "decision": "DECLINE",
    "score": 520,
    "rulesFired": ["CREDIT_BAND_3", "DTI_EXCEED"],
    "reasons": ["DTI exceeds policy limit", "Credit score below minimum"],
}

BLAZE_REFER = {
    "decision": "REFER",
    "score": 650,
    "rulesFired": ["CREDIT_BAND_2", "MANUAL_REVIEW_TRIGGER"],
    "reasons": ["Near boundary — manual review required"],
}

ODM_APPROVE = {"decision": "APPROVE", "rulesFired": ["ELIG_001", "RISK_002"]}
ODM_DECLINE = {"decision": "DECLINE", "rulesFired": ["ELIG_001", "RISK_FAIL"]}


# ---------------------------------------------------------------------------
# Commitment format
# ---------------------------------------------------------------------------

class TestCommitmentFormat:
    def test_commit_returns_sha256_prefix(self):
        assert _commit({"key": "value"}).startswith("sha256:")

    def test_commit_deterministic(self):
        data = {"credit_score": 750, "dti": 0.30}
        assert _commit(data) == _commit(data)

    def test_commit_key_order_independent(self):
        assert _commit({"z": 1, "a": 2}) == _commit({"a": 2, "z": 1})


# ---------------------------------------------------------------------------
# Blaze Init
# ---------------------------------------------------------------------------

class TestFicoBlazeInit:
    def test_url_trailing_slash(self):
        c = FicoBlazeConnector(
            blaze_server_url="https://blaze.test/",
            blaze_api_key="k",
            primust_api_key="pk",
            ruleset_name="TestRuleset",
        )
        assert c.blaze_url == "https://blaze.test"

    def test_stores_ruleset_name(self):
        c = FicoBlazeConnector(
            blaze_server_url="https://blaze.test",
            blaze_api_key="k",
            primust_api_key="pk",
            ruleset_name="MortgageV4",
        )
        assert c.ruleset_name == "MortgageV4"


# ---------------------------------------------------------------------------
# Blaze Manifests
# ---------------------------------------------------------------------------

class TestBlazeManifests:
    def test_has_5_stages(self):
        assert len(BLAZE_MANIFEST_CREDIT_DECISIONING["stages"]) == 5

    def test_all_stages_attestation_today(self):
        for stage in BLAZE_MANIFEST_CREDIT_DECISIONING["stages"]:
            assert stage["proof_level"] == "attestation"

    def test_has_dti_formula(self):
        dti_stage = [
            s for s in BLAZE_MANIFEST_CREDIT_DECISIONING["stages"]
            if s["name"] == "dti_calculation"
        ]
        assert len(dti_stage) == 1
        assert "formula" in dti_stage[0]

    def test_all_stages_have_regulatory_references(self):
        for stage in BLAZE_MANIFEST_CREDIT_DECISIONING["stages"]:
            assert "regulatory_references" in stage
            assert len(stage["regulatory_references"]) > 0

    def test_stages_reference_ecoa(self):
        refs = set()
        for stage in BLAZE_MANIFEST_CREDIT_DECISIONING["stages"]:
            refs.update(stage["regulatory_references"])
        assert "cfpb_ecoa" in refs

    @patch("primust_connectors.credit_brms.primust")
    def test_register_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 1
        assert "fico_blaze_credit_decisioning" in c._manifest_ids


# ---------------------------------------------------------------------------
# Blaze Evaluate
# ---------------------------------------------------------------------------

class TestBlazeEvaluate:
    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_approve_decision(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "Ruleset1")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(
            pipeline=mock_pipeline,
            application_id="APP-001",
            applicant_data={"credit_score": 780, "dti": 0.28, "ltv": 0.75},
        )

        assert isinstance(result, PrimustDecisionRecord)
        assert result.decision == "APPROVE"
        assert result.platform == "fico_blaze"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_decline_decision(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_DECLINE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "Ruleset1")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(
            pipeline=mock_pipeline,
            application_id="APP-002",
            applicant_data={"credit_score": 520, "dti": 0.55},
        )

        assert result.decision == "DECLINE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_refer_is_fail(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_REFER)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(
            pipeline=mock_pipeline,
            application_id="APP-003",
            applicant_data={"credit_score": 650},
        )

        assert result.decision == "REFER"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_input_uses_commitment_hash(self, mock_client_cls):
        """Input must be a commitment hash dict, not raw applicant data."""
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        app_data = {"credit_score": 750, "dti": 0.30, "ltv": 0.80}
        c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data=app_data)

        record_call = mock_pipeline.record.call_args
        input_arg = record_call.kwargs["input"]
        assert isinstance(input_arg, dict)
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_output_commitment_present(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        record_call = mock_pipeline.record.call_args
        input_arg = record_call.kwargs["input"]
        assert "output_commitment" in input_arg
        assert input_arg["output_commitment"].startswith("sha256:")

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_reason_codes_not_in_details(self, mock_client_cls):
        """Reason codes reveal ruleset internals — must not appear."""
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_DECLINE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "reasons" not in details
        assert "rules_fired" not in details
        assert "DTI exceeds" not in str(details)
        assert "reason_count" in details

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_default_visibility_opaque(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    def test_requires_manifest(self):
        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        with pytest.raises(RuntimeError):
            c.evaluate(pipeline=MagicMock(), application_id="A1", applicant_data={})


# ---------------------------------------------------------------------------
# Blaze Gap Codes
# ---------------------------------------------------------------------------

class TestBlazeGapCodes:
    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_api_error_records_gap(self, mock_client_cls):
        import httpx
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response,
        )
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        assert isinstance(result, PrimustDecisionRecord)
        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "blaze_api_error"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_auth_failure_records_critical_gap(self, mock_client_cls):
        import httpx
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=mock_response,
        )
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "blaze_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_404_records_service_not_found(self, mock_client_cls):
        import httpx
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_response,
        )
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "blaze_service_not_found"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_generic_exception_records_gap(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = ConnectionError("Network unreachable")
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.evaluate(pipeline=mock_pipeline, application_id="A1", applicant_data={})

        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "blaze_api_error"


# ---------------------------------------------------------------------------
# Blaze Convenience Wrappers
# ---------------------------------------------------------------------------

class TestBlazeConvenienceWrappers:
    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_execute_credit_decision(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.execute_credit_decision(
            pipeline=mock_pipeline,
            application_id="A1",
            applicant_data={"credit_score": 780},
        )

        assert result.decision == "APPROVE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_execute_aml_screening(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(BLAZE_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = FicoBlazeConnector("http://b", "k", "pk", "R")
        c._manifest_ids["fico_blaze_credit_decisioning"] = "sha256:test"

        result = c.execute_aml_screening(
            pipeline=mock_pipeline,
            application_id="A1",
            screening_data={"entity_type": "INDIVIDUAL"},
        )

        assert isinstance(result, PrimustDecisionRecord)


# ---------------------------------------------------------------------------
# BlazeAdvisorJava demand-gate
# ---------------------------------------------------------------------------

class TestBlazeAdvisorJava:
    def test_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Java SDK"):
            BlazeAdvisorJava()


# ---------------------------------------------------------------------------
# IBM ODM
# ---------------------------------------------------------------------------

class TestIBMODM:
    def test_odm_manifest_has_3_stages(self):
        assert len(ODM_MANIFEST_UNDERWRITING["stages"]) == 3

    def test_odm_manifest_has_regulatory_references(self):
        for stage in ODM_MANIFEST_UNDERWRITING["stages"]:
            assert "regulatory_references" in stage
            assert len(stage["regulatory_references"]) > 0

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_approve(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ODM_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "MyApp", "1.0", "UnderwriteRS")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        result = c.execute_decision(
            pipeline=mock_pipeline,
            request_id="REQ-001",
            decision_input={"applicant_age": 35, "income": 80000},
        )

        assert result.platform == "ibm_odm"
        assert result.decision == "APPROVE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_decline(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ODM_DECLINE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "A", "1.0", "R")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        result = c.execute_decision(
            pipeline=mock_pipeline,
            request_id="REQ-002",
            decision_input={},
        )

        assert result.decision == "DECLINE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_uses_commitment_hash(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ODM_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "A", "1.0", "R")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        c.execute_decision(pipeline=mock_pipeline, request_id="R1", decision_input={"x": 1})

        record_call = mock_pipeline.record.call_args
        input_arg = record_call.kwargs["input"]
        assert isinstance(input_arg, dict)
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_endpoint_format(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ODM_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm.test", "k", "pk", "CreditApp", "2.0", "UnderwriteRS", "1.5")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        c.execute_decision(pipeline=mock_pipeline, request_id="R1", decision_input={})

        mock_client = mock_client_cls.return_value.__enter__.return_value
        post_call = mock_client.post.call_args
        expected_url = "http://odm.test/DecisionService/rest/v1/CreditApp/2.0/UnderwriteRS/1.5"
        assert post_call[0][0] == expected_url

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_accept_is_pass(self, mock_client_cls):
        """ODM can return ACCEPT instead of APPROVE — both should be pass."""
        mock_client_cls.return_value = _mock_httpx_client({"decision": "ACCEPT"})
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "A", "1", "R")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        c.execute_decision(pipeline=mock_pipeline, request_id="R1", decision_input={})
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_visibility_opaque(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ODM_APPROVE)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "A", "1.0", "R")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        c.execute_decision(pipeline=mock_pipeline, request_id="R1", decision_input={})

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.credit_brms.httpx.Client")
    def test_odm_api_error_records_gap(self, mock_client_cls):
        import httpx
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Error", request=MagicMock(), response=mock_response,
        )
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = IBMODMConnector("http://odm", "k", "pk", "A", "1.0", "R")
        c._manifest_ids["ibm_odm_underwriting"] = "sha256:test"

        result = c.execute_decision(pipeline=mock_pipeline, request_id="R1", decision_input={})

        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "odm_api_error"


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

class TestFitValidation:
    def test_blaze_strong(self):
        assert BLAZE_FIT_VALIDATION["fit"] == "STRONG"

    def test_odm_strong(self):
        assert ODM_FIT_VALIDATION["fit"] == "STRONG"

    def test_both_cross_run_consistency(self):
        assert BLAZE_FIT_VALIDATION["cross_run_consistency_applicable"] is True
        assert ODM_FIT_VALIDATION["cross_run_consistency_applicable"] is True

    def test_both_buildable_today(self):
        assert BLAZE_FIT_VALIDATION["buildable_today"] is True
        assert ODM_FIT_VALIDATION["buildable_today"] is True

    def test_odm_has_unique_advantage(self):
        assert "getRulesFired" in ODM_FIT_VALIDATION["unique_advantage"]

    def test_blaze_attestation_ceiling_today(self):
        """Hold-firm: Blaze REST ceiling is Attestation, not Mathematical."""
        assert BLAZE_FIT_VALIDATION["proof_ceiling_today"] == "attestation"
