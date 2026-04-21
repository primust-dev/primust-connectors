"""
PegaDecisioningConnector — comprehensive tests.

Tests:
  - NBA decision flow
  - Credit decision flow (OCC/CFPB context)
  - OAuth2 token handling
  - Privacy invariants (no reason codes, no propensity)
  - Attestation ceiling (permanent — honest characterization)
  - PARTIAL fit validation
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.pega_decisioning import (
    PegaDecisioningConnector,
    PrimustPegaRecord,
    MANIFEST_NBA_DECISION,
    MANIFEST_CREDIT_ACTION,
    MANIFEST_GDPR_AUTOMATED_DECISION,
    FIT_VALIDATION,
)


def _mock_record_result(**kw):
    r = MagicMock()
    r.commitment_hash = kw.get("commitment_hash", "sha256:abc")
    r.record_id = kw.get("record_id", "rec_001")
    r.proof_level = kw.get("proof_level", "attestation")
    return r


def _make_connector(**kw):
    return PegaDecisioningConnector(
        pega_server_url=kw.get("url", "https://pega.test"),
        pega_client_id=kw.get("client_id", "pega_client"),
        pega_client_secret=kw.get("client_secret", "pega_secret"),
        primust_api_key=kw.get("primust_key", "pk_test"),
    )


PEGA_NBA_RESPONSE = {
    "actions": [
        {
            "actionName": "CreditLimitIncrease",
            "group": "Retention",
            "propensity": 0.85,
            "treatmentID": "TR-001",
        },
        {
            "actionName": "BalanceTransferOffer",
            "group": "Acquisition",
            "propensity": 0.62,
            "treatmentID": "TR-002",
        },
    ]
}

PEGA_NBA_EMPTY = {"actions": []}

PEGA_CREDIT_INCREASE = {
    "content": {
        "Decision": "INCREASE",
        "NewCreditLimit": 15000.0,
        "ReasonCodes": ["GOOD_PAYMENT_HISTORY", "LOW_UTILIZATION"],
    }
}

PEGA_CREDIT_DECLINE = {
    "content": {
        "Decision": "DECLINE",
        "NewCreditLimit": None,
        "ReasonCodes": ["HIGH_DTI", "RECENT_DELINQUENCY"],
    }
}

PEGA_TOKEN_RESPONSE = {
    "access_token": "jwt_test_token_abc",
    "token_type": "bearer",
    "expires_in": 3600,
}


class TestPegaInit:
    def test_url_trailing_slash(self):
        c = PegaDecisioningConnector("https://pega.test/", "c", "s", "pk")
        assert c.pega_url == "https://pega.test"

    def test_initial_state(self):
        c = _make_connector()
        assert c._manifest_ids == {}
        assert c._access_token is None


class TestPegaManifests:
    def test_nba_manifest_has_3_stages(self):
        assert len(MANIFEST_NBA_DECISION["stages"]) == 3

    def test_all_nba_stages_attestation(self):
        """Pega engine is opaque — all stages attestation permanently."""
        for stage in MANIFEST_NBA_DECISION["stages"]:
            assert stage["proof_level"] == "attestation"

    def test_credit_manifest_has_3_stages(self):
        assert len(MANIFEST_CREDIT_ACTION["stages"]) == 3

    def test_gdpr_manifest_has_1_stage(self):
        assert len(MANIFEST_GDPR_AUTOMATED_DECISION["stages"]) == 1

    def test_all_credit_stages_attestation(self):
        for stage in MANIFEST_CREDIT_ACTION["stages"]:
            assert stage["proof_level"] == "attestation"

    @patch("primust_connectors.pega_decisioning.primust")
    def test_register_3_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 3
        assert len(c._manifest_ids) == 3


class TestNBADecision:
    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_decision_returns_top_action(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_NBA_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"
        c._access_token = "cached_token"

        result = c.get_nba_decision(
            pipeline=mock_pipeline,
            customer_id="CUST-001",
            channel="web",
        )

        assert isinstance(result, PrimustPegaRecord)
        assert result.decision == "CreditLimitIncrease"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_input_commitment_format(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_NBA_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"
        c._access_token = "token"

        c.get_nba_decision(
            pipeline=mock_pipeline,
            customer_id="CUST-XYZ",
            channel="mobile",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["input"] == "CUST-XYZ|mobile"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_no_propensity_in_details(self, mock_client_cls):
        """Propensity score reveals internal ranking — must NOT appear."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_NBA_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"
        c._access_token = "token"

        c.get_nba_decision(pipeline=mock_pipeline, customer_id="C1")

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "propensity" not in details
        assert 0.85 not in details.values()

    def test_requires_manifest(self):
        c = _make_connector()
        try:
            c.get_nba_decision(pipeline=MagicMock(), customer_id="C1")
            assert False
        except RuntimeError:
            pass


class TestCreditDecision:
    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_credit_increase(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_CREDIT_INCREASE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        result = c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="CUST-002",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={"income": 85000, "bureau_score": 740},
        )

        assert result.decision == "INCREASE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_credit_decline_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_CREDIT_DECLINE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        result = c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="CUST-003",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={"income": 30000, "bureau_score": 580},
        )

        assert result.decision == "DECLINE"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_no_reason_codes_in_details(self, mock_client_cls):
        """Reason codes reveal decision criteria."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_CREDIT_DECLINE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="C",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={},
        )

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]
        assert "reason_codes" not in details
        assert "ReasonCodes" not in details
        assert "HIGH_DTI" not in str(details)
        # reason_code_count is OK — aggregate stat
        assert "reason_code_count" in details


class TestOAuth:
    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_token_cached(self, mock_client_cls):
        c = _make_connector()
        c._access_token = "cached_jwt"

        result = c._get_token()
        assert result == "cached_jwt"
        # Should not make HTTP call if cached
        mock_client_cls.assert_not_called()

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_token_fetched_when_missing(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = PEGA_TOKEN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        token = c._get_token()

        assert token == "jwt_test_token_abc"
        assert c._access_token == "jwt_test_token_abc"


class TestParsing:
    def test_parse_nba_response(self):
        c = _make_connector()
        result = c._parse_nba_response(PEGA_NBA_RESPONSE, "C1")
        assert result.top_action == "CreditLimitIncrease"
        assert result.action_group == "Retention"
        assert result.propensity == 0.85

    def test_parse_nba_empty(self):
        c = _make_connector()
        result = c._parse_nba_response(PEGA_NBA_EMPTY, "C1")
        assert result.top_action == ""

    def test_parse_credit_increase(self):
        c = _make_connector()
        result = c._parse_credit_response(PEGA_CREDIT_INCREASE, "C1")
        assert result.decision == "INCREASE"
        assert result.new_limit == 15000.0
        assert len(result.reason_codes) == 2

    def test_parse_credit_decline(self):
        c = _make_connector()
        result = c._parse_credit_response(PEGA_CREDIT_DECLINE, "C1")
        assert result.decision == "DECLINE"
        assert result.new_limit is None


class TestFitValidation:
    def test_partial_fit(self):
        assert "PARTIAL" in FIT_VALIDATION["fit"]

    def test_honest_fit_note(self):
        assert "Only valuable for regulated" in FIT_VALIDATION["fit_note"]

    def test_attestation_permanent(self):
        """Java SDK does NOT change the ceiling — explicitly called out."""
        assert "attestation" in FIT_VALIDATION["proof_ceiling"]

    def test_java_sdk_irrelevant(self):
        assert FIT_VALIDATION["java_sdk_changes_ceiling"] is False

    def test_has_gdpr_hook(self):
        hooks = FIT_VALIDATION["regulatory_hooks"]
        assert any("GDPR" in h for h in hooks)

    def test_cross_run_consistency(self):
        assert FIT_VALIDATION["cross_run_consistency_applicable"] is True
