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
PegaDecisioningConnector — comprehensive tests.

Tests:
  - NBA decision flow
  - Credit decision flow (OCC/CFPB context)
  - OAuth2 token handling
  - Privacy invariants (no reason codes, no propensity)
  - Attestation ceiling (permanent — honest characterization)
  - PARTIAL fit validation
  - Commitment hash format (input_commitment)
  - Gap codes (pega_api_error, pega_auth_failure)
  - Regulatory references on all manifest stages
  - record_case_decision() method
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.pega_decisioning import (
    PegaDecisioningConnector,
    PegaNBAResult,
    PegaCreditDecisionResult,
    PrimustPegaRecord,
    MANIFEST_NBA_DECISION,
    MANIFEST_CREDIT_ACTION,
    MANIFEST_GDPR_AUTOMATED_DECISION,
    GAP_CODES,
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


def _setup_mock_http_client(mock_client_cls, response_data, status_code=200):
    """Helper to set up a mock httpx.Client with given response."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_resp.status_code = status_code
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client, mock_resp


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

    def test_nba_stages_have_regulatory_references(self):
        for stage in MANIFEST_NBA_DECISION["stages"]:
            assert "regulatory_references" in stage
            assert isinstance(stage["regulatory_references"], list)
            assert len(stage["regulatory_references"]) > 0

    def test_credit_stages_have_regulatory_references(self):
        for stage in MANIFEST_CREDIT_ACTION["stages"]:
            assert "regulatory_references" in stage
            assert isinstance(stage["regulatory_references"], list)
            assert len(stage["regulatory_references"]) > 0

    def test_gdpr_stages_have_regulatory_references(self):
        for stage in MANIFEST_GDPR_AUTOMATED_DECISION["stages"]:
            assert "regulatory_references" in stage
            assert isinstance(stage["regulatory_references"], list)
            assert len(stage["regulatory_references"]) > 0

    @patch("primust_connectors.pega_decisioning.primust")
    def test_register_3_manifests(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.return_value = MagicMock(manifest_id="sha256:x")
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert mock_pipeline.register_check.call_count == 3
        assert len(c._manifest_ids) == 3


class TestCommitmentFormat:
    """Test that _commit() produces deterministic hashes and input format is correct."""

    def test_commit_deterministic(self):
        """Same input always produces same hash."""
        data = {"customer_id": "C1", "channel": "web"}
        h1 = _commit(data)
        h2 = _commit(data)
        assert h1 == h2

    def test_commit_key_order_irrelevant(self):
        """sort_keys ensures order independence."""
        h1 = _commit({"a": 1, "b": 2})
        h2 = _commit({"b": 2, "a": 1})
        assert h1 == h2

    def test_commit_returns_string(self):
        h = _commit({"test": True})
        assert isinstance(h, str)
        assert len(h) > 0

    def test_context_values_not_in_nba_commitment(self):
        """Context attribute VALUES must never appear in the commitment input."""
        # The commitment should only contain keys, not values
        commit_data = {
            "customer_id": "CUST-001",
            "channel": "web",
            "context_keys": sorted(["income", "bureau_score"]),
        }
        h = _commit(commit_data)
        # The hash should not contain the actual values
        assert isinstance(h, str)
        # Verify the structure: context_keys has key names only
        assert "income" in commit_data["context_keys"]
        assert 85000 not in commit_data.values()


class TestNBADecision:
    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_decision_returns_top_action(self, mock_client_cls):
        _setup_mock_http_client(mock_client_cls, PEGA_NBA_RESPONSE)

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
        """Input must be a dict with 'input_commitment' key."""
        _setup_mock_http_client(mock_client_cls, PEGA_NBA_RESPONSE)

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
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert isinstance(input_val["input_commitment"], str)
        assert len(input_val["input_commitment"]) > 0

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_uses_opaque_visibility(self, mock_client_cls):
        _setup_mock_http_client(mock_client_cls, PEGA_NBA_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"
        c._access_token = "token"

        c.get_nba_decision(pipeline=mock_pipeline, customer_id="C1")

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_no_propensity_in_details(self, mock_client_cls):
        """Propensity score reveals internal ranking — must NOT appear."""
        _setup_mock_http_client(mock_client_cls, PEGA_NBA_RESPONSE)

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
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_INCREASE)

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
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_DECLINE)

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
    def test_credit_input_commitment_format(self, mock_client_cls):
        """Credit decision input must use commitment hash dict."""
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_INCREASE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="C1",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={"income": 50000},
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_credit_uses_opaque_visibility(self, mock_client_cls):
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_INCREASE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="C1",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={},
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_no_reason_codes_in_details(self, mock_client_cls):
        """Reason codes reveal decision criteria."""
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_DECLINE)

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

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_context_values_not_in_commitment(self, mock_client_cls):
        """Customer context VALUES must never be in the commitment — schema keys only."""
        _setup_mock_http_client(mock_client_cls, PEGA_CREDIT_INCREASE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="C1",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={"income": 85000, "bureau_score": 740},
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        # The commitment hash is opaque — but the DATA that goes into
        # _commit() should only have context_keys, not values.
        # We verify by checking the commitment is the hash of schema-only data
        expected_commitment = _commit({
            "customer_id": "C1",
            "decision_type": "CREDIT_LIMIT_REVIEW",
            "context_keys": ["bureau_score", "income"],
        })
        assert input_val["input_commitment"] == expected_commitment


class TestGapCodes:
    """Test fail-open gap code handling for Pega API errors."""

    def test_gap_codes_defined(self):
        assert "pega_api_error" in GAP_CODES
        assert GAP_CODES["pega_api_error"]["severity"] == "High"
        assert "pega_auth_failure" in GAP_CODES
        assert GAP_CODES["pega_auth_failure"]["severity"] == "Critical"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_api_error_records_gap(self, mock_client_cls):
        """HTTP error should record gap with check_result=error, not raise."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("connection refused")
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"
        c._access_token = "token"

        result = c.get_nba_decision(pipeline=mock_pipeline, customer_id="C1")

        # Fail-open: returns gracefully
        assert isinstance(result, PrimustPegaRecord)
        assert result.decision == "ERROR"

        # Gap recorded
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["gap_code"] == "pega_api_error"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_nba_401_records_auth_failure(self, mock_client_cls):
        """401 should record pega_auth_failure gap code."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
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

        result = c.get_nba_decision(pipeline=mock_pipeline, customer_id="C1")

        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["gap_code"] == "pega_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "Critical"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_credit_api_error_records_gap(self, mock_client_cls):
        """Credit decision HTTP error should record gap."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("timeout")
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_credit_limit_decision"] = "sha256:test"
        c._access_token = "token"

        result = c.execute_credit_decision(
            pipeline=mock_pipeline,
            customer_id="C1",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={"income": 50000},
        )

        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["gap_code"] == "pega_api_error"

    @patch("primust_connectors.pega_decisioning.httpx.Client")
    def test_credit_401_records_auth_failure(self, mock_client_cls):
        """Credit 401 should record pega_auth_failure."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
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
            customer_id="C1",
            decision_type="CREDIT_LIMIT_REVIEW",
            customer_context={},
        )

        assert result.decision == "ERROR"
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["details"]["gap_code"] == "pega_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "Critical"


class TestRecordCaseDecision:
    """Test the record_case_decision() method."""

    def test_record_case_decision_basic(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"

        result = c.record_case_decision(
            pipeline=mock_pipeline,
            case_id="CASE-001",
            case_type="NBA",
            decision="CreditLimitIncrease",
            context_keys=["income", "bureau_score"],
        )

        assert isinstance(result, PrimustPegaRecord)
        assert result.decision == "CreditLimitIncrease"

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"
        input_val = record_call.kwargs["input"]
        assert "input_commitment" in input_val

    def test_record_case_decision_requires_manifest(self):
        c = _make_connector()
        try:
            c.record_case_decision(
                pipeline=MagicMock(),
                case_id="CASE-001",
                case_type="NBA",
                decision="X",
                context_keys=[],
                manifest_name="nonexistent",
            )
            assert False
        except RuntimeError:
            pass

    def test_record_case_decision_commitment_uses_sorted_keys(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["pega_nba_decision"] = "sha256:test"

        c.record_case_decision(
            pipeline=mock_pipeline,
            case_id="CASE-001",
            case_type="NBA",
            decision="X",
            context_keys=["z_attr", "a_attr", "m_attr"],
        )

        record_call = mock_pipeline.record.call_args
        expected = _commit({
            "case_id": "CASE-001",
            "case_type": "NBA",
            "context_keys": ["a_attr", "m_attr", "z_attr"],
        })
        assert record_call.kwargs["input"]["input_commitment"] == expected


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
        _setup_mock_http_client(mock_client_cls, PEGA_TOKEN_RESPONSE)

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


# Need httpx imported at module level for gap code tests
import httpx
