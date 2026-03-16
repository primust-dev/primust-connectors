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
ComplyAdvantageConnector — comprehensive tests.

Tests:
  - Initialization and configuration
  - Manifest registration
  - Entity screening (pass/fail/sanctions/PEP)
  - Transaction monitoring
  - Privacy invariants (no raw data in VPEC details)
  - Error handling / gap codes
  - Input commitment format (sha256: prefix, PII exclusion)
  - Regulatory references on manifest stages
  - Monitoring alert recording
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.comply_advantage import (
    ComplyAdvantageConnector,
    AMLScreeningResult,
    PrimustAMLRecord,
    MANIFEST_AML_SCREENING,
    MANIFEST_TRANSACTION_MONITORING,
    FIT_VALIDATION,
    _commit,
)


def _mock_record_result(**overrides):
    r = MagicMock()
    r.commitment_hash = overrides.get("commitment_hash", "sha256:abc123")
    r.record_id = overrides.get("record_id", "rec_001")
    r.proof_level = overrides.get("proof_level", "attestation")
    return r


def _mock_manifest_registration(name):
    r = MagicMock()
    r.manifest_id = f"sha256:{name}_id"
    return r


def _make_connector(**kw):
    return ComplyAdvantageConnector(
        ca_api_key=kw.get("ca_api_key", "test_ca_key"),
        primust_api_key=kw.get("primust_api_key", "pk_test_123"),
        fraud_score_threshold=kw.get("fraud_score_threshold", 75.0),
        visibility=kw.get("visibility", "opaque"),
    )


CA_CLEAN_RESPONSE = {
    "content": {
        "data": {
            "id": "search_123",
            "hits": [],
            "risk_level": "low",
            "risk_score": 0.0,
        }
    }
}

CA_SANCTIONS_RESPONSE = {
    "content": {
        "data": {
            "id": "search_456",
            "hits": [
                {"doc": {"types": ["sanction"], "name": "Bad Actor"}},
            ],
            "risk_level": "very_high",
            "risk_score": 95.0,
        }
    }
}

CA_PEP_RESPONSE = {
    "content": {
        "data": {
            "id": "search_789",
            "hits": [
                {"doc": {"types": ["pep-class-1"], "name": "Politician"}},
            ],
            "risk_level": "medium",
            "risk_score": 40.0,
        }
    }
}

CA_ADVERSE_MEDIA_RESPONSE = {
    "content": {
        "data": {
            "id": "search_101",
            "hits": [
                {"doc": {"types": ["adverse-media-financial-crime"], "name": "Company X"}},
            ],
            "risk_level": "high",
            "risk_score": 80.0,
        }
    }
}


def _setup_mock_httpx(mock_client_cls, response_data):
    """Helper to set up mock httpx client with a given response."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = response_data
    mock_resp.raise_for_status = MagicMock()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value = mock_client
    return mock_client


def _setup_mock_httpx_error(mock_client_cls, status_code=500):
    """Helper to set up mock httpx client that raises HTTPStatusError."""
    import httpx as real_httpx
    mock_response = MagicMock()
    mock_response.status_code = status_code
    error = real_httpx.HTTPStatusError(
        message="error",
        request=MagicMock(),
        response=mock_response,
    )
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.side_effect = error
    mock_client_cls.return_value = mock_client
    return mock_client


class TestComplyAdvantageInit:
    def test_default_threshold(self):
        c = _make_connector()
        assert c.fraud_score_threshold == 75.0

    def test_custom_threshold(self):
        c = _make_connector(fraud_score_threshold=50.0)
        assert c.fraud_score_threshold == 50.0

    def test_default_visibility(self):
        c = _make_connector()
        assert c.visibility == "opaque"

    def test_custom_visibility(self):
        c = _make_connector(visibility="selective")
        assert c.visibility == "selective"

    def test_manifest_ids_empty_on_init(self):
        c = _make_connector()
        assert c._manifest_ids == {}


class TestCommitmentFormat:
    def test_commit_returns_sha256_prefix(self):
        result = _commit({"entity_type": "person"})
        assert result.startswith("sha256:")

    def test_commit_deterministic(self):
        data = {"entity_type": "company", "jurisdiction": "US"}
        assert _commit(data) == _commit(data)

    def test_commit_different_data_different_hash(self):
        a = _commit({"entity_type": "person"})
        b = _commit({"entity_type": "company"})
        assert a != b

    def test_commit_key_order_irrelevant(self):
        """sort_keys=True ensures canonical form."""
        a = _commit({"b": 2, "a": 1})
        b = _commit({"a": 1, "b": 2})
        assert a == b


class TestComplyAdvantageManifests:
    def test_manifests_have_required_fields(self):
        for m in [MANIFEST_AML_SCREENING, MANIFEST_TRANSACTION_MONITORING]:
            assert "name" in m
            assert "stages" in m
            assert "aggregation" in m
            assert len(m["stages"]) > 0

    def test_screening_manifest_has_4_stages(self):
        assert len(MANIFEST_AML_SCREENING["stages"]) == 4

    def test_transaction_manifest_has_3_stages(self):
        assert len(MANIFEST_TRANSACTION_MONITORING["stages"]) == 3

    def test_all_stages_attestation(self):
        """ComplyAdvantage is SaaS — all stages attestation."""
        for m in [MANIFEST_AML_SCREENING, MANIFEST_TRANSACTION_MONITORING]:
            for stage in m["stages"]:
                assert stage["proof_level"] == "attestation"

    def test_all_stages_have_regulatory_references(self):
        """Every stage must declare regulatory references."""
        for m in [MANIFEST_AML_SCREENING, MANIFEST_TRANSACTION_MONITORING]:
            for stage in m["stages"]:
                assert "regulatory_references" in stage, (
                    f"Stage {stage['name']} missing regulatory_references"
                )
                assert len(stage["regulatory_references"]) > 0

    def test_screening_manifest_regulatory_tags(self):
        """AML screening stages should reference relevant regulatory frameworks."""
        all_refs = set()
        for stage in MANIFEST_AML_SCREENING["stages"]:
            all_refs.update(stage["regulatory_references"])
        assert "bsa_aml" in all_refs
        assert "ofac_sdn" in all_refs
        assert "fatf_rec10" in all_refs
        assert "eu_amld" in all_refs

    def test_transaction_manifest_regulatory_tags(self):
        """Transaction monitoring stages should reference BSA/AML."""
        all_refs = set()
        for stage in MANIFEST_TRANSACTION_MONITORING["stages"]:
            all_refs.update(stage["regulatory_references"])
        assert "bsa_aml" in all_refs
        assert "bsa_5324_structuring" in all_refs

    @patch("primust_connectors.comply_advantage.primust")
    def test_register_manifests_stores_ids(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.side_effect = [
            _mock_manifest_registration("screening"),
            _mock_manifest_registration("txn_mon"),
        ]
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert "comply_advantage_aml_screening" in c._manifest_ids
        assert "comply_advantage_transaction_monitoring" in c._manifest_ids
        assert mock_pipeline.register_check.call_count == 2


class TestEntityScreening:
    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_clean_entity_passes(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test_manifest"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Clean Corp",
            entity_type="company",
            country_code="US",
        )

        assert isinstance(result, PrimustAMLRecord)
        assert result.screening_result.has_sanctions_match is False
        assert result.screening_result.total_hits == 0

        # Verify pipeline.record was called with "pass"
        call_kwargs = mock_pipeline.record.call_args
        assert call_kwargs.kwargs.get("check_result") == "pass" or call_kwargs[1].get("check_result") == "pass"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_sanctions_match_fails(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_SANCTIONS_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Bad Actor",
            entity_type="person",
        )

        assert result.screening_result.has_sanctions_match is True
        # Sanctions match -> fail regardless of score
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "fail"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_high_risk_score_fails(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_ADVERSE_MEDIA_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(fraud_score_threshold=75.0)
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Company X",
            entity_type="company",
        )

        # risk_score=80 >= threshold=75 -> fail
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "fail"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_pep_match_below_threshold_passes(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_PEP_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(fraud_score_threshold=75.0)
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Politician",
            entity_type="person",
        )

        # PEP but no sanctions, score 40 < 75 -> pass
        assert result.screening_result.has_pep_match is True
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "pass"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_input_commitment_is_hash_dict(self, mock_client_cls):
        """Input should be a dict with 'input_commitment' key, not a pipe-delimited string."""
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="John Doe",
            entity_type="person",
            country_code="GB",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert input_val["input_commitment"].startswith("sha256:")

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_input_commitment_no_country(self, mock_client_cls):
        """Without country_code, commitment should still be a hash dict."""
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Entity",
            entity_type="company",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert input_val["input_commitment"].startswith("sha256:")

    def test_screen_entity_requires_manifest_registration(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.screen_entity(pipeline=mock_pipeline, entity_name="Test")
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestPIIExclusion:
    """Verify that PII fields (entity name, DOB, address) never appear in commitment data."""

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_entity_name_not_in_commitment(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="John Secret Doe",
            entity_type="person",
            country_code="US",
            date_of_birth="1990-01-15",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]

        # The commitment hash is opaque; verify by reconstructing what fields were committed
        # The commitment should be of non-PII fields only
        expected_commitment = _commit({
            "entity_type": "person",
            "jurisdiction": "US",
            "filters": ["sanction", "warning", "fitness-probity", "pep", "adverse-media"],
        })
        assert input_val["input_commitment"] == expected_commitment

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_counterparty_name_not_in_txn_commitment(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_secret",
            amount=50000.0,
            currency="USD",
            counterparty_name="Secret Corp",
            counterparty_country="DE",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]

        # Verify commitment uses only non-PII fields
        expected_commitment = _commit({
            "entity_type": "company",
            "jurisdiction": "DE",
            "filters": ["sanction", "warning", "pep"],
        })
        assert input_val["input_commitment"] == expected_commitment


class TestGapCodeHandling:
    """Verify fail-open gap code handling for API errors."""

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_api_error_records_gap_and_returns(self, mock_client_cls):
        """General API error (non-401) should record gap with high severity."""
        _setup_mock_httpx_error(mock_client_cls, status_code=500)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Test Entity",
            entity_type="person",
        )

        # Should return gracefully (fail-open)
        assert isinstance(result, PrimustAMLRecord)

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "complyadvantage_api_error"
        assert record_call.kwargs["details"]["severity"] == "high"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_auth_failure_records_critical_gap(self, mock_client_cls):
        """401 should record gap with critical severity."""
        _setup_mock_httpx_error(mock_client_cls, status_code=401)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Test Entity",
            entity_type="person",
        )

        assert isinstance(result, PrimustAMLRecord)

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "complyadvantage_auth_failure"
        assert record_call.kwargs["details"]["severity"] == "critical"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_transaction_api_error_records_gap(self, mock_client_cls):
        """Transaction monitoring API error should also record gap."""
        _setup_mock_httpx_error(mock_client_cls, status_code=503)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_transaction_monitoring"] = "sha256:test"

        result = c.monitor_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_001",
            amount=1000.0,
            currency="USD",
            counterparty_name="Vendor",
            counterparty_country="US",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "complyadvantage_api_error"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_generic_exception_records_gap(self, mock_client_cls):
        """Non-HTTP exceptions should also record a gap."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = ConnectionError("network down")
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Test",
            entity_type="person",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "error"
        assert record_call.kwargs["details"]["error_type"] == "complyadvantage_api_error"


class TestTransactionMonitoring:
    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_clean_transaction_passes(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_transaction_monitoring"] = "sha256:test"

        result = c.monitor_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_001",
            amount=1500.00,
            currency="USD",
            counterparty_name="Clean Vendor",
            counterparty_country="US",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "pass"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_sanctions_counterparty_fails(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_SANCTIONS_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_002",
            amount=50000.00,
            currency="USD",
            counterparty_name="Bad Actor",
            counterparty_country="IR",
        )

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_transaction_input_commitment_is_hash_dict(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_transaction_monitoring"] = "sha256:test"

        c.monitor_transaction(
            pipeline=mock_pipeline,
            transaction_id="txn_003",
            amount=9999.99,
            currency="EUR",
            counterparty_name="Euro Corp",
            counterparty_country="DE",
        )

        record_call = mock_pipeline.record.call_args
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert "input_commitment" in input_val
        assert input_val["input_commitment"].startswith("sha256:")

    def test_monitor_transaction_requires_manifest(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.monitor_transaction(
                pipeline=mock_pipeline,
                transaction_id="t1",
                amount=100,
                currency="USD",
                counterparty_name="X",
                counterparty_country="US",
            )
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestMonitoringAlert:
    def test_record_monitoring_alert(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.record_monitoring_alert(
            pipeline=mock_pipeline,
            search_id="search_999",
            alert_type="sanction",
            risk_level="very_high",
            jurisdiction="US",
        )

        assert isinstance(result, PrimustAMLRecord)
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["check_result"] == "fail"
        assert record_call.kwargs["details"]["error_type"] == "complyadvantage_hit_detected"
        assert record_call.kwargs["details"]["severity"] == "high"
        assert record_call.kwargs["visibility"] == "opaque"

        # Input should be commitment hash dict
        input_val = record_call.kwargs["input"]
        assert isinstance(input_val, dict)
        assert input_val["input_commitment"].startswith("sha256:")

    def test_record_monitoring_alert_requires_manifest(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.record_monitoring_alert(
                pipeline=mock_pipeline,
                search_id="s1",
                alert_type="pep",
                risk_level="medium",
            )
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestPrivacyInvariants:
    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_no_match_details_in_record_details(self, mock_client_cls):
        """Match details (which lists flagged, match names) must NOT appear in details."""
        _setup_mock_httpx(mock_client_cls, CA_SANCTIONS_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        c.screen_entity(pipeline=mock_pipeline, entity_name="Bad Actor", entity_type="person")

        record_call = mock_pipeline.record.call_args
        details = record_call.kwargs["details"]

        # These must NOT be in details — revealing enables circumvention
        assert "match_names" not in details
        assert "match_types" not in details
        assert "raw_response" not in details
        assert "search_term" not in details
        assert "entity_name" not in details
        # These are OK — aggregate stats only
        assert "total_hits" in details
        assert "risk_level" in details

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_visibility_always_opaque(self, mock_client_cls):
        _setup_mock_httpx(mock_client_cls, CA_CLEAN_RESPONSE)

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"
        c.screen_entity(pipeline=mock_pipeline, entity_name="Test", entity_type="person")

        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs["visibility"] == "opaque"


class TestFitValidation:
    def test_fit_is_strong(self):
        assert FIT_VALIDATION["fit"] == "STRONG"

    def test_has_regulatory_hooks(self):
        assert len(FIT_VALIDATION["regulatory_hooks"]) > 0

    def test_trust_deficit(self):
        assert FIT_VALIDATION["trust_deficit"] is True

    def test_proof_ceiling_attestation(self):
        assert FIT_VALIDATION["proof_ceiling"] == "attestation"

    def test_buildable_today(self):
        assert FIT_VALIDATION["buildable_today"] is True

    def test_aml_paradox_resolved(self):
        assert FIT_VALIDATION["aml_paradox_resolved"] is True


class TestParseScreeningResponse:
    def test_parse_empty_hits(self):
        c = _make_connector()
        result = c._parse_screening_response(CA_CLEAN_RESPONSE)
        assert result.total_hits == 0
        assert result.has_sanctions_match is False
        assert result.has_pep_match is False
        assert result.has_adverse_media is False
        assert result.risk_level == "low"

    def test_parse_sanctions_hit(self):
        c = _make_connector()
        result = c._parse_screening_response(CA_SANCTIONS_RESPONSE)
        assert result.has_sanctions_match is True
        assert result.total_hits == 1

    def test_parse_pep_hit(self):
        c = _make_connector()
        result = c._parse_screening_response(CA_PEP_RESPONSE)
        assert result.has_pep_match is True
        assert result.has_sanctions_match is False

    def test_parse_adverse_media(self):
        c = _make_connector()
        result = c._parse_screening_response(CA_ADVERSE_MEDIA_RESPONSE)
        assert result.has_adverse_media is True
