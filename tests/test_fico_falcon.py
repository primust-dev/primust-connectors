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
FicoFalconConnector — comprehensive tests.

Tests:
  - Transaction scoring (approve/decline/review threshold logic)
  - Privacy invariants (no score or thresholds in details)
  - PCI compliance (card_number_hash parameter)
  - Input commitment format (hash dict, no card/account numbers)
  - Gap codes (API errors, auth failures)
  - Regulatory references on all manifest stages
  - Commitment format validation
  - Rules decision recording
  - PARTIAL fit validation
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.fico_falcon import (
    FicoFalconConnector,
    FalconScoreResult,
    PrimustFraudRecord,
    MANIFEST_FRAUD_SCORE,
    MANIFEST_BATCH_AUTHORIZATION,
    MANIFEST_RULES_DECISION,
    FIT_VALIDATION,
    _commit,
    _score_to_band,
)


def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    return r


def _make_connector(**kw):
    return FicoFalconConnector(
        falcon_server_url=kw.get("url", "https://falcon.test"),
        falcon_api_key=kw.get("api_key", "falcon_key"),
        primust_api_key=kw.get("primust_key", "pk_test"),
        decline_threshold=kw.get("decline", 750),
        review_threshold=kw.get("review", 500),
    )


FALCON_LOW_SCORE = {
    "fraudScore": 200,
    "decision": "APPROVE",
    "modelVersion": "falcon_6.3.1",
}

FALCON_HIGH_SCORE = {
    "fraudScore": 850,
    "decision": "DECLINE",
    "modelVersion": "falcon_6.3.1",
}

FALCON_MID_SCORE = {
    "fraudScore": 600,
    "decision": "REVIEW",
    "modelVersion": "falcon_6.3.1",
}


def _setup_mock_httpx(mock_client_cls, response_data):
    """Helper to set up httpx mock with given response data."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client


def _setup_error_httpx(mock_client_cls, status_code=500):
    """Helper to set up httpx mock that raises HTTPStatusError."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    error = httpx.HTTPStatusError(
        message=f"Server error {status_code}",
        request=MagicMock(),
        response=mock_response,
    )
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.side_effect = error
    mock_client_cls.return_value = mock_client
    return mock_client


class TestFalconInit:
    def test_default_thresholds(self):
        c = _make_connector()
        assert c.decline_threshold == 750
        assert c.review_threshold == 500

    def test_custom_thresholds(self):
        c = _make_connector(decline=800, review=600)
        assert c.decline_threshold == 800
        assert c.review_threshold == 600

    def test_url_trailing_slash(self):
        c = FicoFalconConnector("https://falcon.test/", "k", "pk")
        assert c.falcon_url == "https://falcon.test"


class TestCommitmentFormat:
    def test_commit_returns_string(self):
        result = _commit({"key": "value"})
        assert isinstance(result, str)

    def test_commit_deterministic(self):
        """Same data produces same commitment."""
        a = _commit({"x": 1, "y": 2})
        b = _commit({"y": 2, "x": 1})
        assert a == b

    def test_commit_different_data_different_hash(self):
        a = _commit({"x": 1})
        b = _commit({"x": 2})
        assert a != b


class TestScoreBand:
    def test_low_band(self):
        assert _score_to_band(100) == "low"
        assert _score_to_band(399) == "low"

    def test_medium_band(self):
        assert _score_to_band(400) == "medium"
        assert _score_to_band(699) == "medium"

    def test_high_band(self):
        assert _score_to_band(700) == "high"
        assert _score_to_band(999) == "high"


class TestFalconManifests:
    def test_fraud_score_manifest_has_3_stages(self):
        assert len(MANIFEST_FRAUD_SCORE["stages"]) == 3

    def test_batch_auth_manifest_has_3_stages(self):
        assert len(MANIFEST_BATCH_AUTHORIZATION["stages"]) == 3

    def test_rules_decision_manifest_has_1_stage(self):
        assert len(MANIFEST_RULES_DECISION["stages"]) == 1

    def test_neural_net_stage_is_attestation(self):
        nn_stage = MANIFEST_FRAUD_SCORE["stages"][0]
        assert nn_stage["name"] == "neural_net_scoring"
        assert nn_stage["type"] == "ml_model"
        assert nn_stage["proof_level"] == "attestation"

    def test_threshold_stages_are_deterministic(self):
        for stage in MANIFEST_FRAUD_SCORE["stages"][1:]:
            assert stage["type"] == "deterministic_rule"
            assert stage["method"] == "threshold_comparison"

    def test_threshold_value_not_in_manifest(self):
        """Threshold numeric values must NOT be in the manifest — revealing enables gaming."""
        manifest_str = str(MANIFEST_FRAUD_SCORE)
        assert "750" not in manifest_str
        assert "500" not in manifest_str

    def test_all_fraud_score_stages_have_regulatory_references(self):
        for stage in MANIFEST_FRAUD_SCORE["stages"]:
            assert "regulatory_references" in stage, f"Stage {stage['name']} missing regulatory_references"
            assert len(stage["regulatory_references"]) > 0

    def test_all_batch_auth_stages_have_regulatory_references(self):
        for stage in MANIFEST_BATCH_AUTHORIZATION["stages"]:
            assert "regulatory_references" in stage, f"Stage {stage['name']} missing regulatory_references"
            assert len(stage["regulatory_references"]) > 0

    def test_all_rules_decision_stages_have_regulatory_references(self):
        for stage in MANIFEST_RULES_DECISION["stages"]:
            assert "regulatory_references" in stage, f"Stage {stage['name']} missing regulatory_references"
            assert len(stage["regulatory_references"]) > 0

    @patch("primust_connectors.fico_falcon.primust")
    def test_register_3_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 3
        assert len(c._manifest_ids) == 3


class TestScoreTransaction:
    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_low_score_approves(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, FALCON_LOW_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_001",
            card_number_hash="sha256:card_hash_abc",
            amount=125.50,
            merchant_id="MID_001",
            merchant_category_code="5411",
            country_code="US",
        )

        assert isinstance(result, PrimustFraudRecord)
        assert result.decision == "APPROVE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_high_score_declines(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, FALCON_HIGH_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(decline=750)
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_002",
            card_number_hash="sha256:card_hash_xyz",
            amount=9999.99,
            merchant_id="MID_SUS",
            merchant_category_code="7995",
            country_code="NG",
        )

        assert result.decision == "DECLINE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_mid_score_review(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, FALCON_MID_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(decline=750, review=500)
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_003",
            card_number_hash="sha256:card_mid",
            amount=500.00,
            merchant_id="MID_002",
            merchant_category_code="5999",
            country_code="US",
        )

        # 600 >= 500 (review) but < 750 (decline) → REVIEW
        assert result.decision == "REVIEW"
        record_call = mock_pipeline.record.call_args
        # REVIEW is not DECLINE → pass
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_input_commitment_is_hash_dict(self, mock_client_cls):
        """Input must be a dict with input_commitment key (not pipe-delimited string)."""
        _setup_mock_httpx(mock_client_cls, FALCON_LOW_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="sha256:hash_abc",
            amount=42.00,
            merchant_id="M1",
            merchant_category_code="5411",
            country_code="GB",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert isinstance(input_val["input_commitment"], str)

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_card_number_not_in_input_commitment(self, mock_client_cls):
        """Card number must NEVER be in the input commitment — PCI requirement."""
        _setup_mock_httpx(mock_client_cls, FALCON_LOW_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        card_hash = "sha256:hash_abc"
        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash=card_hash,
            amount=42.00,
            merchant_id="M1",
            merchant_category_code="5411",
            country_code="GB",
        )

        # The commitment hash for safe fields only should differ from one that includes card hash
        safe_commitment = _commit({
            "transaction_id": "t1",
            "merchant_id": "M1",
            "merchant_category_code": "5411",
            "country_code": "GB",
            "amount": 42.00,
        })
        with_card_commitment = _commit({
            "transaction_id": "t1",
            "card_number_hash": card_hash,
            "merchant_id": "M1",
            "merchant_category_code": "5411",
            "country_code": "GB",
            "amount": 42.00,
        })
        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert input_val["input_commitment"] == safe_commitment
        assert input_val["input_commitment"] != with_card_commitment

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_model_score_band_in_details(self, mock_client_cls):
        """Details should contain model_score_band, NOT raw fraud score."""
        _setup_mock_httpx(mock_client_cls, FALCON_HIGH_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "model_score_band" in details
        assert details["model_score_band"] == "high"
        assert "fraud_score" not in details
        assert "fraudScore" not in details

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_visibility_always_opaque(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, FALCON_LOW_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"


class TestGapCodes:
    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_api_error_records_gap(self, mock_client_cls):
        """Falcon API error should record a gap, not raise."""
        _setup_error_httpx(mock_client_cls, status_code=500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        assert result.decision == "ERROR"
        assert result.gap_code == "falcon_api_error"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "falcon_api_error"
        assert record_call.kwargs["details"]["severity"] == "high"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_auth_failure_records_critical_gap(self, mock_client_cls):
        """401 auth failure should record a critical gap."""
        _setup_error_httpx(mock_client_cls, status_code=401)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        assert result.decision == "ERROR"
        assert result.gap_code == "falcon_auth_failure"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "falcon_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_gap_records_input_commitment(self, mock_client_cls):
        """Even on error, input commitment should be recorded."""
        _setup_error_httpx(mock_client_cls, status_code=500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_gap_visibility_opaque(self, mock_client_cls):
        """Gap records should also use opaque visibility."""
        _setup_error_httpx(mock_client_cls, status_code=500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_generic_exception_records_gap(self, mock_client_cls):
        """Non-HTTP errors should also record a gap gracefully."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = ConnectionError("network down")
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        result = c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        assert result.decision == "ERROR"
        assert result.gap_code == "falcon_api_error"


class TestRulesDecision:
    def test_record_rules_decision_approve(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_rules_decision"] = "sha256:rules"

        result = c.record_rules_decision(
            pipeline=mock_pipeline,
            transaction_id="t1",
            rules_triggered=["velocity_24h"],
            rules_decision="APPROVE",
            merchant_id="M1",
            merchant_category_code="5411",
            country_code="US",
        )

        assert result.decision == "APPROVE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"
        assert record_call.kwargs["visibility"] == "opaque"

    def test_record_rules_decision_decline(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_rules_decision"] = "sha256:rules"

        result = c.record_rules_decision(
            pipeline=mock_pipeline,
            transaction_id="t1",
            rules_triggered=["velocity_24h", "geo_anomaly"],
            rules_decision="DECLINE",
            merchant_id="M1",
            merchant_category_code="5411",
            country_code="RU",
        )

        assert result.decision == "DECLINE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"
        details = record_call.kwargs["details"]
        assert details["rules_triggered_count"] == 2
        # Individual rule IDs should NOT be in details — reveals fraud strategy
        assert "velocity_24h" not in str(details)

    def test_record_rules_decision_input_commitment(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_rules_decision"] = "sha256:rules"

        c.record_rules_decision(
            pipeline=mock_pipeline,
            transaction_id="t1",
            rules_triggered=[],
            rules_decision="APPROVE",
            merchant_id="M1",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val

    def test_rules_requires_manifest(self):
        c = _make_connector()
        try:
            c.record_rules_decision(
                pipeline=MagicMock(),
                transaction_id="t1",
                rules_triggered=[],
                rules_decision="APPROVE",
                merchant_id="M1",
                merchant_category_code="5411",
                country_code="US",
            )
            assert False, "Should have raised RuntimeError"
        except RuntimeError:
            pass


class TestPrivacyInvariants:
    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_no_fraud_score_in_details(self, mock_client_cls):
        """Fraud score reveals position relative to threshold — must NOT appear."""
        _setup_mock_httpx(mock_client_cls, FALCON_HIGH_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "fraud_score" not in details
        assert "fraudScore" not in details
        assert 850 not in details.values()

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_no_thresholds_in_details(self, mock_client_cls):
        """Threshold values must NOT appear in details."""
        _setup_mock_httpx(mock_client_cls, FALCON_LOW_SCORE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(decline=750, review=500)
        c._manifest_ids["fico_falcon_fraud_score"] = "sha256:test"

        c.score_transaction(
            pipeline=mock_pipeline,
            transaction_id="t1",
            card_number_hash="h",
            amount=100,
            merchant_id="m",
            merchant_category_code="5411",
            country_code="US",
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "decline_threshold" not in details
        assert "review_threshold" not in details
        assert 750 not in details.values()
        assert 500 not in details.values()

    def test_mathematical_stage_note_in_result(self):
        """PrimustFraudRecord includes a note about mathematical threshold stage."""
        r = PrimustFraudRecord(
            commitment_hash="h",
            record_id="r",
            proof_level="attestation",
            decision="APPROVE",
        )
        assert "Mathematical" in r.mathematical_stage_note

    def test_requires_manifest(self):
        c = _make_connector()
        try:
            c.score_transaction(
                pipeline=MagicMock(),
                transaction_id="t1",
                card_number_hash="h",
                amount=100,
                merchant_id="m",
                merchant_category_code="5411",
                country_code="US",
            )
            assert False
        except RuntimeError:
            pass


class TestFitValidation:
    def test_partial_fit(self):
        assert FIT_VALIDATION["fit"] == "PARTIAL"

    def test_honest_fit_note(self):
        assert "internal risk management" in FIT_VALIDATION["fit_note"]

    def test_cross_run_consistency(self):
        assert FIT_VALIDATION["cross_run_consistency_applicable"] is True

    def test_buildable_today(self):
        assert FIT_VALIDATION["buildable_today"] is True

    def test_proof_ceiling_mixed(self):
        """Score = attestation permanent, threshold = mathematical post-Java."""
        post_java = FIT_VALIDATION["proof_ceiling_post_java_sdk"]
        assert "attestation" in post_java["score_computation"]
        assert "mathematical" in post_java["threshold_comparison"]

    def test_java_sdk_note(self):
        assert FIT_VALIDATION["sdk_required_for_mathematical"] is not None
