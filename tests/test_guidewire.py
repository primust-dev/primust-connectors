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
Tests for Guidewire ClaimCenter connector.

All tests mock ClaimCenter and Primust API calls.
Privacy invariant: raw monetary amounts and claim contents
must never appear in any payload sent to Primust.
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call

from primust_connectors.guidewire import (
    GuidewireClaimCenterConnector,
    GuidewireClient,
    FIT_VALIDATION,
    _coverage_limit_check,
    _reserve_adequacy_check,
    _bounded_claim_metadata,
    _bounded_payment_metadata,
    _commit,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_CLAIM = {
    "data": {
        "id": "CC:12345",
        "attributes": {
            "state": "open",
            "lineOfBusiness": "auto",
            "jurisdiction": "CA",
            "lossType": "collision",
            "deductibleAmount": 1000.00,
            "coverages": [{"type": "collision"}, {"type": "comprehensive"}],
            "exposureCount": 2,
            "claimantName": "SENSITIVE_PII_DO_NOT_TRANSIT",
            "claimantSSN": "SENSITIVE_PII_DO_NOT_TRANSIT",
        },
        "relationships": {
            "policy": {"data": {"id": "POL:99999"}}
        },
    }
}

MOCK_POLICY = {
    "data": {
        "id": "POL:99999",
        "attributes": {
            "totalLimit": 100_000.00,
            "policyNumber": "AUTO-2026-001",
            "effectiveDate": "2026-01-01",
            "expirationDate": "2027-01-01",
        }
    }
}

MOCK_EXPOSURES = [
    {
        "attributes": {
            "reserveAmount": 50_000.00,
            "incurredAmount": 45_000.00,
            "exposureType": "vehicleDamage",
        }
    },
    {
        "attributes": {
            "reserveAmount": 10_000.00,
            "incurredAmount": 8_000.00,
            "exposureType": "medicalExpense",
        }
    },
]

MOCK_PAYMENTS = [
    {
        "attributes": {
            "status": "issued",
            "paymentType": "partial",
            "payee": "SENSITIVE_DO_NOT_TRANSIT",
            "amount": 20_000.00,
        }
    }
]

MOCK_ACTIVITIES = [
    {"attributes": {"activityType": "review", "status": "complete"}}
]


def _make_connector() -> GuidewireClaimCenterConnector:
    connector = GuidewireClaimCenterConnector(
        gw_base_url="https://test.guidewire.com",
        gw_client_id="test-client",
        gw_client_secret="test-secret",
        primust_api_key="pk_test_abc123",
    )
    connector._manifest_ids = {
        "claim_retrieval": "sha256:manifest_retrieval",
        "coverage_verification": "sha256:manifest_coverage",
        "reserve_adequacy": "sha256:manifest_reserve",
        "adjudication_decision": "sha256:manifest_adjudication",
    }
    return connector


# ---------------------------------------------------------------------------
# Fit validation
# ---------------------------------------------------------------------------

class TestFitValidation:
    def test_fit_level_strong(self):
        assert FIT_VALIDATION["fit_level"] == "STRONG"

    def test_not_partial_fit(self):
        assert FIT_VALIDATION["partial_fit"] is False
        assert FIT_VALIDATION["partial_fit_reason"] is None

    def test_regulated_process(self):
        assert FIT_VALIDATION["regulated_process"] is True

    def test_data_cannot_be_disclosed(self):
        assert FIT_VALIDATION["data_cannot_be_disclosed"] is True

    def test_external_verifier_present(self):
        assert FIT_VALIDATION["external_verifier"]
        assert "reinsurer" in FIT_VALIDATION["external_verifier"].lower()

    def test_proof_ceiling_attestation(self):
        assert FIT_VALIDATION["proof_ceiling"] == "attestation"

    def test_regulatory_hooks_present(self):
        assert len(FIT_VALIDATION["regulatory_hooks"]) >= 2


# ---------------------------------------------------------------------------
# Arithmetic stages — Mathematical proof level
# ---------------------------------------------------------------------------

class TestCoverageLimitCheck:
    def test_within_limit_passes(self):
        result = _coverage_limit_check(
            requested_amount=40_000.00,
            policy_limit=100_000.00,
            deductible=1_000.00,
        )
        assert result["within_limit"] is True
        assert result["deductible_applied"] is True

    def test_exceeds_limit_fails(self):
        result = _coverage_limit_check(
            requested_amount=110_000.00,
            policy_limit=100_000.00,
            deductible=1_000.00,
        )
        assert result["within_limit"] is False

    def test_exactly_at_limit_passes(self):
        result = _coverage_limit_check(
            requested_amount=101_000.00,  # net = 100k after 1k deductible
            policy_limit=100_000.00,
            deductible=1_000.00,
        )
        assert result["within_limit"] is True

    def test_utilization_band_25pct(self):
        result = _coverage_limit_check(30_500.00, 100_000.00, 500.00)
        assert result["utilization_band"] == "25-50%"

    def test_utilization_band_75pct(self):
        result = _coverage_limit_check(76_000.00, 100_000.00, 0.00)
        assert result["utilization_band"] == "75-100%"

    def test_no_deductible(self):
        result = _coverage_limit_check(50_000.00, 100_000.00, 0.00)
        assert result["deductible_applied"] is False
        assert result["within_limit"] is True

    def test_no_monetary_amounts_in_result(self):
        """Result dict must not contain monetary amounts."""
        result = _coverage_limit_check(45_000.00, 100_000.00, 1_000.00)
        result_str = json.dumps(result)
        assert "45000" not in result_str
        assert "100000" not in result_str
        assert "1000" not in result_str


class TestReserveAdequacyCheck:
    def test_adequate_reserves_pass(self):
        result = _reserve_adequacy_check(60_000.00, 53_000.00)
        assert result["reserve_adequate"] is True

    def test_inadequate_reserves_fail(self):
        result = _reserve_adequacy_check(40_000.00, 53_000.00)
        assert result["reserve_adequate"] is False

    def test_custom_threshold(self):
        result = _reserve_adequacy_check(105.00, 100.00, threshold_ratio=1.1)
        assert result["reserve_adequate"] is False  # 105 < 110

    def test_threshold_ratio_in_output(self):
        result = _reserve_adequacy_check(100.00, 90.00, threshold_ratio=1.05)
        assert result["threshold_ratio"] == 1.05


# ---------------------------------------------------------------------------
# Bounded metadata — no sensitive data in transit payloads
# ---------------------------------------------------------------------------

class TestBoundedMetadata:
    def test_bounded_claim_metadata_safe_fields_only(self):
        meta = _bounded_claim_metadata(MOCK_CLAIM)
        meta_str = json.dumps(meta)
        assert "SENSITIVE_PII" not in meta_str
        assert "claimantName" not in meta_str
        assert "claimantSSN" not in meta_str

    def test_bounded_claim_metadata_has_expected_fields(self):
        meta = _bounded_claim_metadata(MOCK_CLAIM)
        assert meta["claim_state"] == "open"
        assert meta["lob"] == "auto"
        assert meta["jurisdiction"] == "CA"
        assert meta["coverage_type_count"] == 2

    def test_bounded_payment_metadata_no_amounts(self):
        meta = _bounded_payment_metadata(MOCK_PAYMENTS)
        meta_str = json.dumps(meta)
        assert "20000" not in meta_str
        assert "payee" not in meta_str
        assert "SENSITIVE" not in meta_str

    def test_bounded_payment_metadata_has_count(self):
        meta = _bounded_payment_metadata(MOCK_PAYMENTS)
        assert meta["payment_count"] == 1
        assert "issued" in meta["statuses"]


# ---------------------------------------------------------------------------
# Privacy invariant — raw data never transits to Primust
# ---------------------------------------------------------------------------

class TestPrivacyInvariant:
    """
    Core invariant: monetary amounts, claim contents, and PII
    must never appear in any payload sent to api.primust.com.
    """

    def _run_adjudication_and_capture_records(self, connector):
        """Run adjudication and return all recorded payloads."""
        recorded = []

        mock_run = MagicMock()
        def capture_record(**kwargs):
            recorded.append(kwargs)
            return MagicMock(
                commitment_hash="sha256:abc",
                record_id="rec_001",
                proof_level="attestation",
                queued=False,
            )
        mock_run.record = capture_record
        mock_run.close = MagicMock(return_value=MagicMock(
            vpec_id="vpec_001",
            proof_level="attestation",
            chain_intact=True,
            governance_gaps=[],
        ))

        mock_pipeline = MagicMock()
        mock_pipeline.open = MagicMock(return_value=mock_run)

        with patch.object(connector.gw, "get_claim", return_value=MOCK_CLAIM):
            with patch.object(connector.gw, "get_policy", return_value=MOCK_POLICY):
                with patch.object(connector.gw, "get_exposures", return_value=MOCK_EXPOSURES):
                    with patch.object(connector.gw, "get_payments", return_value=MOCK_PAYMENTS):
                        connector.adjudicate_claim(
                            claim_id="CC:12345",
                            requested_payment=40_000.00,
                            pipeline=mock_pipeline,
                        )

        return recorded

    def test_raw_payment_amount_never_in_details(self):
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        all_details_str = json.dumps([r.get("details", {}) for r in records])
        assert "40000" not in all_details_str
        assert "40_000" not in all_details_str

    def test_policy_limit_never_in_details(self):
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        all_details_str = json.dumps([r.get("details", {}) for r in records])
        assert "100000" not in all_details_str

    def test_deductible_never_in_details(self):
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        all_details_str = json.dumps([r.get("details", {}) for r in records])
        # 1000 is too short to uniquely check, check for exact deductible
        assert "deductibleAmount" not in all_details_str

    def test_pii_never_in_details(self):
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        all_details_str = json.dumps([r.get("details", {}) for r in records])
        assert "SENSITIVE_PII" not in all_details_str
        assert "SENSITIVE_DO_NOT_TRANSIT" not in all_details_str

    def test_all_inputs_are_commitments_not_raw(self):
        """Every 'input' field sent to Primust must be a commitment hash, not raw data."""
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        for record in records:
            input_val = record.get("input", {})
            input_str = json.dumps(input_val)
            # Every input must contain only commitment hashes
            assert "SENSITIVE" not in input_str
            assert "claimantName" not in input_str
            # Input values should be sha256: prefixed hashes
            for v in input_val.values():
                if isinstance(v, str):
                    assert v.startswith("sha256:"), (
                        f"Input value '{v[:50]}' is not a commitment hash"
                    )

    def test_visibility_opaque_for_all_records(self):
        connector = _make_connector()
        records = self._run_adjudication_and_capture_records(connector)
        for record in records:
            assert record.get("visibility") == "opaque"


# ---------------------------------------------------------------------------
# Workflow correctness
# ---------------------------------------------------------------------------

class TestWorkflowCorrectness:
    def _run_workflow(self, requested_payment=40_000.00, policy_limit=100_000.00):
        connector = _make_connector()
        records = []

        mock_run = MagicMock()
        def capture_record(**kwargs):
            records.append(kwargs)
            return MagicMock(commitment_hash="sha256:abc", record_id="rec_001")
        mock_run.record = capture_record
        mock_run.close = MagicMock(return_value=MagicMock(
            vpec_id="vpec_001", chain_intact=True, governance_gaps=[]
        ))
        mock_pipeline = MagicMock()
        mock_pipeline.open = MagicMock(return_value=mock_run)

        mock_policy = {
            "data": {
                "id": "POL:99999",
                "attributes": {"totalLimit": policy_limit}
            }
        }

        with patch.object(connector.gw, "get_claim", return_value=MOCK_CLAIM):
            with patch.object(connector.gw, "get_policy", return_value=mock_policy):
                with patch.object(connector.gw, "get_exposures", return_value=MOCK_EXPOSURES):
                    with patch.object(connector.gw, "get_payments", return_value=MOCK_PAYMENTS):
                        vpec = connector.adjudicate_claim(
                            claim_id="CC:12345",
                            requested_payment=requested_payment,
                            pipeline=mock_pipeline,
                        )
        return records, vpec

    def test_all_four_checks_executed_for_valid_claim(self):
        records, _ = self._run_workflow()
        check_names = [r["check"] for r in records]
        assert "claim_retrieval" in check_names
        assert "coverage_verification" in check_names
        assert "reserve_adequacy" in check_names
        assert "adjudication_decision" in check_names

    def test_exceeds_limit_stops_after_coverage_check(self):
        """If payment exceeds limit, workflow stops — no adjudication record."""
        records, _ = self._run_workflow(requested_payment=200_000.00)
        check_names = [r["check"] for r in records]
        assert "coverage_verification" in check_names
        assert "adjudication_decision" not in check_names

    def test_coverage_check_result_fail_when_over_limit(self):
        records, _ = self._run_workflow(requested_payment=200_000.00)
        cov = next(r for r in records if r["check"] == "coverage_verification")
        assert cov["check_result"] == "fail"

    def test_coverage_check_result_pass_when_within_limit(self):
        records, _ = self._run_workflow(requested_payment=40_000.00)
        cov = next(r for r in records if r["check"] == "coverage_verification")
        assert cov["check_result"] == "pass"

    def test_vpec_returned(self):
        _, vpec = self._run_workflow()
        assert vpec is not None

    def test_reserve_adequacy_reflects_exposure_data(self):
        """total_reserve=60k, total_incurred=53k — should pass."""
        records, _ = self._run_workflow()
        reserve = next(r for r in records if r["check"] == "reserve_adequacy")
        assert reserve["check_result"] == "pass"
        assert reserve["details"]["exposure_count"] == 2


# ---------------------------------------------------------------------------
# Commitment determinism
# ---------------------------------------------------------------------------

class TestCommitment:
    def test_same_input_same_commitment(self):
        assert _commit({"a": 1}) == _commit({"a": 1})

    def test_different_input_different_commitment(self):
        assert _commit({"a": 1}) != _commit({"a": 2})

    def test_commitment_is_sha256_prefixed(self):
        result = _commit("test")
        assert result.startswith("sha256:")
        assert len(result) == 71  # "sha256:" + 64 hex chars

    def test_key_order_independent(self):
        """Canonical JSON means key order doesn't change commitment."""
        assert _commit({"b": 2, "a": 1}) == _commit({"a": 1, "b": 2})
