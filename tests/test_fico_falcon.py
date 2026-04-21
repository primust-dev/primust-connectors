"""
FicoFalconConnector — comprehensive tests.

Tests:
  - Transaction scoring (approve/decline/review threshold logic)
  - Privacy invariants (no score or thresholds in details)
  - PCI compliance (card_number_hash parameter)
  - Input commitment format
  - PARTIAL fit validation
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.fico_falcon import (
    FicoFalconConnector,
    PrimustFraudRecord,
    MANIFEST_FRAUD_SCORE,
    MANIFEST_BATCH_AUTHORIZATION,
    FIT_VALIDATION,
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


class TestFalconManifests:
    def test_fraud_score_manifest_has_3_stages(self):
        assert len(MANIFEST_FRAUD_SCORE["stages"]) == 3

    def test_batch_auth_manifest_has_3_stages(self):
        assert len(MANIFEST_BATCH_AUTHORIZATION["stages"]) == 3

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
        # Numeric threshold values must not appear
        assert "750" not in manifest_str
        assert "500" not in manifest_str
        # Stage names referencing thresholds are OK — they describe the check type,
        # not the actual threshold value

    @patch("primust_connectors.fico_falcon.primust")
    def test_register_2_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 2
        assert len(c._manifest_ids) == 2


class TestScoreTransaction:
    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_low_score_approves(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_LOW_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_HIGH_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_MID_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
    def test_input_commitment_format(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_LOW_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        assert record_call.kwargs["input"] == "sha256:hash_abc|42.0|M1|5411|GB"


class TestPrivacyInvariants:
    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_no_fraud_score_in_details(self, mock_client_cls):
        """Fraud score reveals position relative to threshold — must NOT appear."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_HIGH_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_LOW_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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

    @patch("primust_connectors.fico_falcon.httpx.Client")
    def test_default_visibility_opaque(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = FALCON_LOW_SCORE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
