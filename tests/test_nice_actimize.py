"""
NiceActimizeConnector — comprehensive tests.

Tests:
  - Transaction monitoring (alert/no-alert)
  - SAR determination workflow (Witnessed level)
  - Privacy invariants (no rule codes in details)
  - Input commitment format
  - Manifest structure
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.nice_actimize import (
    NiceActimizeConnector,
    SARDecisionResult,
    PrimustAMLRecord,
    MANIFEST_TRANSACTION_MONITORING,
    MANIFEST_KYC_REFRESH,
    MANIFEST_SAR_DECISION,
    FIT_VALIDATION,
)


def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    return r


def _make_connector(**kw):
    return NiceActimizeConnector(
        actimize_server_url=kw.get("url", "https://actimize.test.internal"),
        actimize_api_key=kw.get("api_key", "act_key_123"),
        primust_api_key=kw.get("primust_key", "pk_test_456"),
        alert_score_threshold=kw.get("threshold", 0.65),
    )


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


class TestActimizeInit:
    def test_url_trailing_slash_stripped(self):
        c = NiceActimizeConnector(
            actimize_server_url="https://server.com/",
            actimize_api_key="k",
            primust_api_key="pk",
        )
        assert c.actimize_url == "https://server.com"

    def test_default_threshold(self):
        c = _make_connector()
        assert c.alert_score_threshold == 0.65

    def test_custom_threshold(self):
        c = _make_connector(threshold=0.8)
        assert c.alert_score_threshold == 0.8


class TestActimizeManifests:
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
        for m in [
            MANIFEST_TRANSACTION_MONITORING,
            MANIFEST_KYC_REFRESH,
            MANIFEST_SAR_DECISION,
        ]:
            assert "aggregation" in m

    @patch("primust_connectors.nice_actimize.primust")
    def test_register_3_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 3
        assert len(c._manifest_ids) == 3


class TestTransactionMonitoring:
    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_no_alert_passes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ACTIMIZE_NO_ALERT
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
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
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_alert_generated_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = ACTIMIZE_ALERT
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        result = c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="acct_002",
            transaction_id="txn_002",
            amount=9800.00,
            transaction_type="ACH",
        )

        assert result.alert_generated is True
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_input_commitment_includes_amount(self, mock_client_cls):
        """Amount must be in the input commitment for cross-run consistency."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = ACTIMIZE_NO_ALERT
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="acct_X",
            transaction_id="txn_Y",
            amount=7500.50,
            transaction_type="WIRE",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["input"] == "acct_X|txn_Y|7500.5|WIRE"

    @patch("primust_connectors.nice_actimize.httpx.Client")
    def test_rule_codes_not_in_details(self, mock_client_cls):
        """Rule codes reveal monitoring methodology — must NOT appear in details."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = ACTIMIZE_ALERT
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["actimize_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            account_id="a",
            transaction_id="t",
            amount=100,
            transaction_type="ACH",
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "rule_codes_fired" not in details
        assert "ruleCodesFired" not in details
        assert "VEL_001" not in str(details)

    def test_requires_manifest_registration(self):
        c = _make_connector()
        try:
            c.monitor_transaction(
                pipeline=MagicMock(),
                account_id="a",
                transaction_id="t",
                amount=100,
                transaction_type="ACH",
            )
            assert False, "Should raise"
        except RuntimeError:
            pass


class TestSARDetermination:
    def test_sar_file_determination(self):
        c = _make_connector()
        c._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_pipeline = MagicMock()
        mock_review = MagicMock()
        mock_review.open_tst = "base64_timestamp"
        mock_pipeline.open_review.return_value = mock_review

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

        # Verify open_review was called with correct params
        review_call = mock_pipeline.open_review.call_args
        assert review_call.kwargs["reviewer_key_id"] == "analyst_bob"
        assert review_call.kwargs["min_duration_seconds"] == 1800  # 30 * 60

    def test_sar_no_file_determination(self):
        c = _make_connector()
        c._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_pipeline = MagicMock()
        mock_pipeline.open_review.return_value = MagicMock()

        result = c.record_sar_determination(
            pipeline=mock_pipeline,
            case_id="CASE-2024-002",
            determination="NO_FILE",
            analyst_key_id="analyst_alice",
            case_content_hash="sha256:case_hash",
            rationale="False positive — legitimate business pattern",
            reviewer_signature="ed25519_sig_xyz",
        )

        assert result.determination == "NO_FILE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    def test_sar_review_includes_signature(self):
        c = _make_connector()
        c._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_pipeline = MagicMock()
        mock_pipeline.open_review.return_value = MagicMock()

        c.record_sar_determination(
            pipeline=mock_pipeline,
            case_id="C1",
            determination="FILE",
            analyst_key_id="k1",
            case_content_hash="h1",
            rationale="reason",
            reviewer_signature="sig_123",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["reviewer_signature"] == "sig_123"
        assert record_call.kwargs["rationale"] == "reason"
        assert record_call.kwargs["display_content"] == "h1"

    def test_sar_visibility_opaque(self):
        """SAR contents are legally protected — must be opaque."""
        c = _make_connector()
        c._manifest_ids["actimize_sar_decision"] = "sha256:test"

        mock_pipeline = MagicMock()
        mock_pipeline.open_review.return_value = MagicMock()

        c.record_sar_determination(
            pipeline=mock_pipeline,
            case_id="C1",
            determination="FILE",
            analyst_key_id="k1",
            case_content_hash="h1",
            rationale="reason",
            reviewer_signature="sig",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"


class TestParseAlertResponse:
    def test_parse_no_alert(self):
        c = _make_connector()
        result = c._parse_alert_response(ACTIMIZE_NO_ALERT)
        assert result.alert_generated is False
        assert result.risk_score == 0.3
        assert result.rule_codes_fired == []

    def test_parse_alert(self):
        c = _make_connector()
        result = c._parse_alert_response(ACTIMIZE_ALERT)
        assert result.alert_generated is True
        assert result.alert_type == "VELOCITY"
        assert len(result.rule_codes_fired) == 3


class TestFitValidation:
    def test_fit_strong(self):
        assert FIT_VALIDATION["fit"] == "STRONG"

    def test_sar_witnessed_level(self):
        assert FIT_VALIDATION["sar_witnessed_level"] is True

    def test_cross_run_consistency(self):
        assert FIT_VALIDATION["cross_run_consistency_applicable"] is True

    def test_aml_paradox_resolved(self):
        assert FIT_VALIDATION["aml_paradox_resolved"] is True
