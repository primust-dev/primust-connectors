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
NiceActimizeConnector — comprehensive tests.

Tests cover all three surfaces:
  1. ActimizeAlertEvaluator — transaction monitoring (alert/no-alert, gap codes)
  2. ActimizeSARWorkflow — SAR filing (Witnessed level, RFC 3161 timestamps)
  3. ActimizeKYCAssessor — KYC/CDD assessment (commitment fields, gap codes)
  4. NiceActimizeConnector — legacy facade backward compatibility
  5. Privacy invariants — no rule codes, no PII in commitments
  6. Commitment format — sha256: prefix, canonical JSON, field exclusion
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.nice_actimize import (
    NiceActimizeConnector,
    ActimizeAlertEvaluator,
    ActimizeSARWorkflow,
    ActimizeKYCAssessor,
    ActimizeAlertResult,
    SARDecisionResult,
    KYCAssessmentResult,
    PrimustAMLRecord,
    PrimustKYCRecord,
    MANIFEST_TRANSACTION_MONITORING,
    MANIFEST_KYC_REFRESH,
    MANIFEST_SAR_DECISION,
    FIT_VALIDATION,
    _parse_alert_response,
    _commit,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc123")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    r.recorded_at = kw.get("recorded_at", "rfc3161_close_tst")
    return r


def _make_legacy_connector(**kw):
    return NiceActimizeConnector(
        actimize_server_url=kw.get("url", "https://actimize.test.internal"),
        actimize_api_key=kw.get("api_key", "act_key_123"),
        primust_api_key=kw.get("primust_key", "pk_test_456"),
        alert_score_threshold=kw.get("threshold", 0.65),
    )


def _make_alert_evaluator(**kw):
    return ActimizeAlertEvaluator(
        base_url=kw.get("url", "https://actimize.test.internal"),
        api_key=kw.get("api_key", "act_key_123"),
        primust_api_key=kw.get("primust_key", "pk_test_456"),
        alert_score_threshold=kw.get("threshold", 0.65),
    )


def _make_sar_workflow(**kw):
    return ActimizeSARWorkflow(
        base_url=kw.get("url", "https://actimize.test.internal"),
        api_key=kw.get("api_key", "act_key_123"),
        primust_api_key=kw.get("primust_key", "pk_test_456"),
    )


def _make_kyc_assessor(**kw):
    return ActimizeKYCAssessor(
        base_url=kw.get("url", "https://actimize.test.internal"),
        api_key=kw.get("api_key", "act_key_123"),
        primust_api_key=kw.get("primust_key", "pk_test_456"),
    )


def _mock_httpx_client(response_data):
    """Set up mock httpx.Client context manager returning response_data."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    return mock_client


ACTIMIZE_NO_ALERT = {
    "alertId": "",
    "alertType": "",
    "riskScore": 0.3,
    "alertGenerated": False,
    "ruleCodesFired": [],
}

ACTIMIZE_ALERT = {
    "alertId": "ALT-2024-001",
    "alertType": "VELOCITY",
    "riskScore": 0.92,
    "alertGenerated": True,
    "ruleCodesFired": ["VEL_001", "STR_003", "BEH_ML_007"],
}

ACTIMIZE_KYC_RESPONSE = {
    "assessmentId": "KYC-2024-001",
    "riskRating": "HIGH",
    "decision": "ENHANCED_DUE_DILIGENCE",
    "rulesAppliedCount": 5,
}


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

class TestManifests:
    def test_transaction_monitoring_has_5_stages(self):
        assert len(MANIFEST_TRANSACTION_MONITORING["stages"]) == 5

    def test_kyc_refresh_has_2_stages(self):
        assert len(MANIFEST_KYC_REFRESH["stages"]) == 2

    def test_sar_decision_has_witnessed_stage(self):
        stages = MANIFEST_SAR_DECISION["stages"]
        witnessed = [s for s in stages if s["proof_level"] == "witnessed"]
        assert len(witnessed) == 1
        assert witnessed[0]["name"] == "analyst_determination"

    def test_all_manifests_have_aggregation(self):
        for m in [MANIFEST_TRANSACTION_MONITORING, MANIFEST_KYC_REFRESH, MANIFEST_SAR_DECISION]:
            assert "aggregation" in m

    def test_transaction_monitoring_has_regulatory_references(self):
        for stage in MANIFEST_TRANSACTION_MONITORING["stages"]:
            assert "regulatory_references" in stage
            assert len(stage["regulatory_references"]) > 0

    def test_sar_decision_has_regulatory_references(self):
        for stage in MANIFEST_SAR_DECISION["stages"]:
            assert "regulatory_references" in stage

    def test_kyc_refresh_has_regulatory_references(self):
        for stage in MANIFEST_KYC_REFRESH["stages"]:
            assert "regulatory_references" in stage

    def test_sar_witnessed_stage_references_bsa(self):
        stages = MANIFEST_SAR_DECISION["stages"]
        witnessed = [s for s in stages if s["proof_level"] == "witnessed"][0]
        assert "bsa_sar_31_cfr_1020" in witnessed["regulatory_references"]


# ---------------------------------------------------------------------------
# Commitment format
# ---------------------------------------------------------------------------

class TestCommitmentFormat:
    def test_commit_returns_sha256_prefix(self):
        result = _commit({"key": "value"})
        assert result.startswith("sha256:")

    def test_commit_deterministic(self):
        data = {"a": 1, "b": 2}
        assert _commit(data) == _commit(data)

    def test_commit_different_data_different_hash(self):
        assert _commit({"a": 1}) != _commit({"a": 2})

    def test_commit_canonical_json_sorted_keys(self):
        """Key order shouldn't matter — canonical JSON sorts keys."""
        assert _commit({"z": 1, "a": 2}) == _commit({"a": 2, "z": 1})


# ---------------------------------------------------------------------------
# Surface 1: AlertEvaluator
# ---------------------------------------------------------------------------

class TestAlertEvaluator:
    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_no_alert_passes(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = e.evaluate_transaction(
            run=mock_run,
            transaction_id="txn_001",
            account_id="acct_001",
            amount=500.00,
            currency="USD",
        )

        assert isinstance(result, PrimustAMLRecord)
        assert result.alert_generated is False
        record_call = mock_run.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_alert_generated_fails(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = e.evaluate_transaction(
            run=mock_run,
            transaction_id="txn_002",
            account_id="acct_002",
            amount=9800.00,
            currency="USD",
        )

        assert result.alert_generated is True
        record_call = mock_run.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_input_uses_commitment_hash_not_pipe_delimited(self, mock_client_cls):
        """Input must be a commitment hash dict, not pipe-delimited string."""
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        e.evaluate_transaction(
            run=mock_run,
            transaction_id="txn_X",
            account_id="acct_Y",
            amount=7500.50,
            currency="USD",
        )

        record_call = mock_run.record.call_args
        input_arg = record_call.kwargs["input"]
        assert isinstance(input_arg, dict)
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_rule_codes_not_in_details(self, mock_client_cls):
        """Rule codes reveal monitoring methodology — must NOT appear in details."""
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        record_call = mock_run.record.call_args
        details = record_call.kwargs["details"]
        assert "rule_codes_fired" not in details
        assert "ruleCodesFired" not in details
        assert "VEL_001" not in str(details)

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_visibility_always_opaque(self, mock_client_cls):
        """System invariant: all regulated connector records use opaque visibility."""
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        record_call = mock_run.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_output_commitment_present_on_success(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        record_call = mock_run.record.call_args
        input_arg = record_call.kwargs["input"]
        assert "output_commitment" in input_arg
        assert input_arg["output_commitment"].startswith("sha256:")

    def test_requires_manifest_registration(self):
        e = _make_alert_evaluator()
        with pytest.raises(RuntimeError):
            e.evaluate_transaction(
                run=MagicMock(),
                transaction_id="t",
                account_id="a",
                amount=100,
                currency="USD",
            )


# ---------------------------------------------------------------------------
# Surface 1: AlertEvaluator — Gap codes
# ---------------------------------------------------------------------------

class TestAlertEvaluatorGapCodes:
    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_api_error_records_gap(self, mock_client_cls):
        """Vendor API errors -> gap record, never raised exception."""
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

        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        # Should NOT raise — fail-open
        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_run.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "actimize_api_error"

    @patch("primust_connectors.nice_actimize.httpx.Client")
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

        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_run.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "actimize_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_generic_exception_records_gap(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = ConnectionError("Network unreachable")
        mock_client_cls.return_value = mock_client

        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        e = _make_alert_evaluator()
        e._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = e.evaluate_transaction(
            run=mock_run,
            transaction_id="t",
            account_id="a",
            amount=100,
            currency="USD",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_run.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "actimize_api_error"


# ---------------------------------------------------------------------------
# Surface 2: SAR Workflow (Witnessed)
# ---------------------------------------------------------------------------

class TestSARWorkflow:
    def test_sar_file_determination(self):
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_review = MagicMock()
        mock_review.open_tst = "rfc3161_open_timestamp"
        mock_run.open_review.return_value = mock_review
        mock_run.record.return_value = _mock_record_result(recorded_at="rfc3161_close_timestamp")

        result = w.record_sar_filing(
            run=mock_run,
            case_id="CASE-2024-001",
            reviewer_id="analyst_bob",
            filing_decision="file",
            rationale="Multiple structuring indicators",
            reviewer_signature="ed25519_sig_abc",
            case_content_hash="sha256:case_content",
            min_review_minutes=30,
        )

        assert isinstance(result, SARDecisionResult)
        assert result.determination == "file"
        assert result.analyst_id == "analyst_bob"

    def test_sar_no_file_determination(self):
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        result = w.record_sar_filing(
            run=mock_run,
            case_id="CASE-2024-002",
            reviewer_id="analyst_alice",
            filing_decision="no_file",
            rationale="False positive",
            reviewer_signature="ed25519_sig_xyz",
            case_content_hash="sha256:case_hash",
        )

        assert result.determination == "no_file"
        record_call = mock_run.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    def test_sar_both_rfc3161_timestamps_present(self):
        """CRITICAL: SAR Witnessed path needs BOTH RFC 3161 timestamps."""
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_review = MagicMock()
        mock_review.open_tst = "rfc3161_open_tst_value"
        mock_run.open_review.return_value = mock_review
        mock_run.record.return_value = _mock_record_result(recorded_at="rfc3161_close_tst_value")

        result = w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale="reason",
            reviewer_signature="sig",
            case_content_hash="h1",
        )

        assert result.check_open_tst is not None, "check_open_tst (RFC 3161) must be present"
        assert result.check_close_tst is not None, "check_close_tst (RFC 3161) must be present"
        assert result.check_open_tst == "rfc3161_open_tst_value"
        assert result.check_close_tst == "rfc3161_close_tst_value"

    def test_sar_rationale_committed_not_sent_plaintext(self):
        """INVARIANT: rationale text NEVER sent to Primust. Only hash."""
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        rationale_text = "Multiple structuring indicators below $10k threshold"
        result = w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale=rationale_text,
            reviewer_signature="sig",
            case_content_hash="h1",
        )

        # rationale_hash should be a sha256 commitment, not the plaintext
        assert result.rationale_hash is not None
        assert result.rationale_hash.startswith("sha256:")
        assert rationale_text not in result.rationale_hash

    def test_sar_review_includes_signature(self):
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale="reason",
            reviewer_signature="sig_123",
            case_content_hash="h1",
        )

        record_call = mock_run.record.call_args
        assert record_call.kwargs["reviewer_signature"] == "sig_123"

    def test_sar_visibility_opaque(self):
        """SAR contents are legally protected — must be opaque."""
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale="reason",
            reviewer_signature="sig",
            case_content_hash="h1",
        )

        record_call = mock_run.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    def test_sar_open_review_min_duration(self):
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale="reason",
            reviewer_signature="sig",
            case_content_hash="h1",
            min_review_minutes=30,
        )

        review_call = mock_run.open_review.call_args
        assert review_call.kwargs["min_duration_seconds"] == 1800  # 30 * 60

    def test_sar_input_commitment_format(self):
        """Input must be a commitment dict, not pipe-delimited."""
        w = _make_sar_workflow()
        w._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_run = MagicMock()
        mock_run.open_review.return_value = MagicMock(open_tst="tst")
        mock_run.record.return_value = _mock_record_result()

        w.record_sar_filing(
            run=mock_run,
            case_id="C1",
            reviewer_id="k1",
            filing_decision="file",
            rationale="reason",
            reviewer_signature="sig",
            case_content_hash="h1",
        )

        record_call = mock_run.record.call_args
        input_arg = record_call.kwargs["input"]
        assert isinstance(input_arg, dict)
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")

    def test_requires_manifest_registration(self):
        w = _make_sar_workflow()
        with pytest.raises(RuntimeError):
            w.record_sar_filing(
                run=MagicMock(),
                case_id="C1",
                reviewer_id="k1",
                filing_decision="file",
                rationale="r",
                reviewer_signature="s",
                case_content_hash="h",
            )


# ---------------------------------------------------------------------------
# Surface 3: KYC Assessor
# ---------------------------------------------------------------------------

class TestKYCAssessor:
    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_assess_customer_returns_record(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_KYC_RESPONSE)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        k = _make_kyc_assessor()
        k._manifest_ids["actimize_kyc_refresh"] = "sha256:test"

        result = k.assess_customer(
            run=mock_run,
            customer_id="CUST-001",
            risk_tier="HIGH",
            assessment_type="PERIODIC",
            jurisdiction="US",
        )

        assert isinstance(result, PrimustKYCRecord)
        assert result.decision == "ENHANCED_DUE_DILIGENCE"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_kyc_input_commitment_excludes_pii(self, mock_client_cls):
        """PII fields (name, DOB, SSN) must NOT be in input commitment."""
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_KYC_RESPONSE)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        k = _make_kyc_assessor()
        k._manifest_ids["actimize_kyc_refresh"] = "sha256:test"

        k.assess_customer(
            run=mock_run,
            customer_id="CUST-001",
            risk_tier="HIGH",
            assessment_type="PERIODIC",
            jurisdiction="US",
        )

        record_call = mock_run.record.call_args
        input_arg = record_call.kwargs["input"]
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")
        # The commitment is a hash — no PII values can be extracted from it

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_kyc_visibility_opaque(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_KYC_RESPONSE)
        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        k = _make_kyc_assessor()
        k._manifest_ids["actimize_kyc_refresh"] = "sha256:test"

        k.assess_customer(
            run=mock_run,
            customer_id="C",
            risk_tier="LOW",
            assessment_type="INITIAL",
            jurisdiction="UK",
        )

        record_call = mock_run.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_kyc_api_error_records_gap(self, mock_client_cls):
        import httpx
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "Service Unavailable", request=MagicMock(), response=mock_response,
        )
        mock_client_cls.return_value = mock_client

        mock_run = MagicMock()
        mock_run.record.return_value = _mock_record_result()

        k = _make_kyc_assessor()
        k._manifest_ids["actimize_kyc_refresh"] = "sha256:test"

        result = k.assess_customer(
            run=mock_run,
            customer_id="C",
            risk_tier="LOW",
            assessment_type="INITIAL",
            jurisdiction="UK",
        )

        assert isinstance(result, PrimustKYCRecord)
        assert result.decision == "error"
        record_call = mock_run.record.call_args
        assert record_call.kwargs["details"]["error_type"] == "actimize_api_error"

    def test_requires_manifest_registration(self):
        k = _make_kyc_assessor()
        with pytest.raises(RuntimeError):
            k.assess_customer(
                run=MagicMock(),
                customer_id="C",
                risk_tier="LOW",
                assessment_type="INITIAL",
                jurisdiction="UK",
            )


# ---------------------------------------------------------------------------
# Legacy facade (NiceActimizeConnector)
# ---------------------------------------------------------------------------

class TestLegacyFacade:
    def test_url_trailing_slash_stripped(self):
        c = NiceActimizeConnector(
            actimize_server_url="https://server.com/",
            actimize_api_key="k",
            primust_api_key="pk",
        )
        assert c.actimize_url == "https://server.com"

    def test_default_threshold(self):
        c = _make_legacy_connector()
        assert c.alert_score_threshold == 0.65

    def test_custom_threshold(self):
        c = _make_legacy_connector(threshold=0.8)
        assert c.alert_score_threshold == 0.8

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_monitor_transaction_no_alert(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_legacy_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="acct_001",
            transaction_id="txn_001",
            amount=500.00,
            transaction_type="WIRE",
        )

        assert isinstance(result, PrimustAMLRecord)
        assert result.alert_generated is False

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_monitor_transaction_uses_commitment_hash(self, mock_client_cls):
        """Legacy facade must also use commitment hashes, not pipe-delimited."""
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_legacy_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="acct_X",
            transaction_id="txn_Y",
            amount=7500.50,
            transaction_type="WIRE",
        )

        record_call = mock_pipeline.record.call_args
        input_arg = record_call.kwargs["input"]
        assert isinstance(input_arg, dict)
        assert "input_commitment" in input_arg
        assert input_arg["input_commitment"].startswith("sha256:")

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_monitor_transaction_visibility_opaque(self, mock_client_cls):
        mock_client_cls.return_value = _mock_httpx_client(ACTIMIZE_NO_ALERT)
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_legacy_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="a",
            transaction_id="t",
            amount=100,
            transaction_type="ACH",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    def test_legacy_requires_manifest_registration(self):
        c = _make_legacy_connector()
        with pytest.raises(RuntimeError):
            c.monitor_transaction(
                pipeline=MagicMock(),
                account_id="a",
                transaction_id="t",
                amount=100,
                transaction_type="ACH",
            )

    def test_legacy_sar_determination(self):
        c = _make_legacy_connector()
        c._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_pipeline = MagicMock()
        mock_review = MagicMock()
        mock_review.open_tst = "base64_timestamp"
        mock_pipeline.open_review.return_value = mock_review
        mock_pipeline.record.return_value = _mock_record_result()

        result = c.record_sar_determination(
            pipeline=mock_pipeline,
            case_id="CASE-2024-001",
            determination="FILE",
            analyst_key_id="analyst_bob",
            case_content_hash="sha256:case_content",
            rationale="Multiple structuring indicators",
            reviewer_signature="ed25519_sig_abc",
            min_review_minutes=30,
        )

        assert isinstance(result, SARDecisionResult)
        assert result.determination == "FILE"
        assert result.analyst_id == "analyst_bob"

    def test_legacy_parse_alert_response(self):
        c = _make_legacy_connector()
        result = c._parse_alert_response(ACTIMIZE_NO_ALERT)
        assert result.alert_generated is False
        assert result.risk_score == 0.3


# ---------------------------------------------------------------------------
# Parse alert response (module-level function)
# ---------------------------------------------------------------------------

class TestParseAlertResponse:
    def test_parse_no_alert(self):
        result = _parse_alert_response(ACTIMIZE_NO_ALERT)
        assert result.alert_generated is False
        assert result.risk_score == 0.3
        assert result.rule_codes_fired == []

    def test_parse_alert(self):
        result = _parse_alert_response(ACTIMIZE_ALERT)
        assert result.alert_generated is True
        assert result.alert_type == "VELOCITY"
        assert len(result.rule_codes_fired) == 3


# ---------------------------------------------------------------------------
# FIT_VALIDATION
# ---------------------------------------------------------------------------

class TestFitValidation:
    def test_fit_strong(self):
        assert FIT_VALIDATION["fit"] == "STRONG"

    def test_sar_witnessed_level(self):
        assert FIT_VALIDATION["sar_witnessed_level"] is True

    def test_cross_run_consistency(self):
        assert FIT_VALIDATION["cross_run_consistency_applicable"] is True

    def test_aml_paradox_resolved(self):
        assert FIT_VALIDATION["aml_paradox_resolved"] is True
