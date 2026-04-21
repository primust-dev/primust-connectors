"""
ComplyAdvantageConnector — comprehensive tests.

Tests:
  - Initialization and configuration
  - Manifest registration
  - Entity screening (pass/fail/sanctions/PEP)
  - Transaction monitoring
  - Privacy invariants (no raw data in VPEC details)
  - Error handling
  - Input commitment format
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.comply_advantage import (
    ComplyAdvantageConnector,
    PrimustAMLRecord,
    MANIFEST_AML_SCREENING,
    MANIFEST_TRANSACTION_MONITORING,
    FIT_VALIDATION,
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
                {
                    "doc": {
                        "types": ["adverse-media-financial-crime"],
                        "name": "Company X",
                    }
                },
            ],
            "risk_level": "high",
            "risk_score": 80.0,
        }
    }
}


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
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        assert (
            call_kwargs.kwargs.get("check_result") == "pass"
            or call_kwargs[1].get("check_result") == "pass"
        )

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_sanctions_match_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_SANCTIONS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        # Sanctions match → fail regardless of score
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "fail"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_high_risk_score_fails(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_ADVERSE_MEDIA_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(fraud_score_threshold=75.0)
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Company X",
            entity_type="company",
        )

        # risk_score=80 >= threshold=75 → fail
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "fail"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_pep_match_below_threshold_passes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_PEP_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector(fraud_score_threshold=75.0)
        c._manifest_ids["comply_advantage_aml_screening"] = "sha256:test"

        result = c.screen_entity(
            pipeline=mock_pipeline,
            entity_name="Politician",
            entity_type="person",
        )

        # PEP but no sanctions, score 40 < 75 → pass
        assert result.screening_result.has_pep_match is True
        record_call = mock_pipeline.record.call_args
        assert record_call.kwargs.get("check_result") == "pass"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_input_commitment_format(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        assert record_call.kwargs["input"] == "John Doe|person|GB"

    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_input_commitment_no_country(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        assert record_call.kwargs["input"] == "Entity|company|"

    def test_screen_entity_requires_manifest_registration(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.screen_entity(pipeline=mock_pipeline, entity_name="Test")
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestTransactionMonitoring:
    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_clean_transaction_passes(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_SANCTIONS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
    def test_transaction_input_commitment_format(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
        assert record_call.kwargs["input"] == "txn_003|Euro Corp|DE"

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


class TestPrivacyInvariants:
    @patch("primust_connectors.comply_advantage.httpx.Client")
    def test_no_match_details_in_record_details(self, mock_client_cls):
        """Match details (which lists flagged, match names) must NOT appear in details."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_SANCTIONS_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
    def test_visibility_default_opaque(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = CA_CLEAN_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

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
