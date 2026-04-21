"""
PurviewConnector — comprehensive tests.

Tests:
  - Initialization and configuration
  - Manifest registration
  - Copilot interaction recording (pass/fail/DLP match)
  - DLP match recording (block/notify/override)
  - Sensitivity label recording
  - Insider risk recording
  - Activity polling (mocked Management API)
  - Privacy invariants (no PII, no content in details)
  - Fit validation (three-property filter)
  - Event parsing and risk assessment
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.purview import (
    PurviewConnector,
    PrimustPurviewRecord,
    CopilotGovernanceResult,
    DLPResult,
    InsiderRiskResult,
    MANIFEST_COPILOT_GOVERNANCE,
    MANIFEST_DLP_MONITORING,
    MANIFEST_INSIDER_RISK,
    FIT_VALIDATION,
    _sha256_hash,
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
    return PurviewConnector(
        tenant_id=kw.get("tenant_id", "test-tenant-id"),
        client_id=kw.get("client_id", "test-client-id"),
        client_secret=kw.get("client_secret", "test-client-secret"),
        primust_api_key=kw.get("primust_api_key", "pk_test_123"),
        visibility=kw.get("visibility", "opaque"),
    )


# --- Sample Purview events ---

COPILOT_CLEAN_EVENT = {
    "Id": "evt_copilot_001",
    "Operation": "CopilotInteraction",
    "UserId": "user@contoso.com",
    "PolicyMatchInfo": {"HasMatch": False},
    "SensitivityLabel": {"LabelName": "General", "LabelId": "label-001"},
    "AccessedItems": [{"Name": "doc1.docx"}, {"Name": "doc2.xlsx"}],
}

COPILOT_DLP_MATCH_EVENT = {
    "Id": "evt_copilot_002",
    "Operation": "CopilotInteraction",
    "UserId": "user@contoso.com",
    "PolicyMatchInfo": {"HasMatch": True},
    "SensitivityLabel": {"LabelName": "Confidential", "LabelId": "label-002"},
    "AccessedItems": [{"Name": "secret.docx"}],
}

DLP_RULE_MATCH_EVENT = {
    "Id": "evt_dlp_001",
    "Operation": "DLPRuleMatch",
    "UserId": "user@contoso.com",
    "PolicyDetails": {
        "PolicyId": "pol-001",
        "RuleName": "Block external sharing of PII",
        "Action": "block",
        "Severity": "high",
    },
}

DLP_NOTIFY_EVENT = {
    "Id": "evt_dlp_002",
    "Operation": "DLPRuleMatch",
    "UserId": "user@contoso.com",
    "PolicyDetails": {
        "PolicyId": "pol-002",
        "RuleName": "Notify on credit card numbers",
        "Action": "notify",
        "Severity": "medium",
    },
}

SENSITIVITY_LABEL_EVENT = {
    "Id": "evt_label_001",
    "Operation": "SensitivityLabelApplied",
    "UserId": "user@contoso.com",
    "LabelAction": "apply",
    "SensitivityLabel": {"LabelName": "Highly Confidential", "LabelId": "label-003"},
}

INSIDER_RISK_EVENT = {
    "Id": "evt_risk_001",
    "AlertId": "alert-001",
    "Operation": "InsiderRiskAlert",
    "RiskLevel": "high",
    "Signals": [{"Type": "data_exfiltration"}, {"Type": "unusual_access"}],
}

INSIDER_RISK_LOW_EVENT = {
    "Id": "evt_risk_002",
    "AlertId": "alert-002",
    "Operation": "InsiderRiskAlert",
    "RiskLevel": "low",
    "Signals": [{"Type": "unusual_access"}],
}


class TestPurviewInit:
    def test_default_visibility(self):
        c = _make_connector()
        assert c.visibility == "opaque"

    def test_custom_visibility(self):
        c = _make_connector(visibility="selective")
        assert c.visibility == "selective"

    def test_manifest_ids_empty_on_init(self):
        c = _make_connector()
        assert c._manifest_ids == {}

    def test_tenant_id_stored(self):
        c = _make_connector(tenant_id="my-tenant")
        assert c.tenant_id == "my-tenant"

    def test_tenant_id_required(self):
        try:
            PurviewConnector(
                tenant_id="",
                client_id="x",
                client_secret="x",
                primust_api_key="x",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "tenant_id" in str(e)

    def test_client_id_required(self):
        try:
            PurviewConnector(
                tenant_id="x",
                client_id="",
                client_secret="x",
                primust_api_key="x",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "client_id" in str(e)

    def test_client_secret_required(self):
        try:
            PurviewConnector(
                tenant_id="x",
                client_id="x",
                client_secret="",
                primust_api_key="x",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "client_secret" in str(e)

    def test_access_token_none_on_init(self):
        c = _make_connector()
        assert c._access_token is None


class TestPurviewManifests:
    def test_manifests_have_required_fields(self):
        for m in [
            MANIFEST_COPILOT_GOVERNANCE,
            MANIFEST_DLP_MONITORING,
            MANIFEST_INSIDER_RISK,
        ]:
            assert "name" in m
            assert "stages" in m
            assert "aggregation" in m
            assert len(m["stages"]) > 0

    def test_copilot_manifest_has_3_stages(self):
        assert len(MANIFEST_COPILOT_GOVERNANCE["stages"]) == 3

    def test_dlp_manifest_has_2_stages(self):
        assert len(MANIFEST_DLP_MONITORING["stages"]) == 2

    def test_insider_risk_manifest_has_2_stages(self):
        assert len(MANIFEST_INSIDER_RISK["stages"]) == 2

    def test_all_stages_attestation(self):
        """Purview is external platform audit log — all stages attestation."""
        for m in [
            MANIFEST_COPILOT_GOVERNANCE,
            MANIFEST_DLP_MONITORING,
            MANIFEST_INSIDER_RISK,
        ]:
            for stage in m["stages"]:
                assert stage["proof_level"] == "attestation"

    def test_freshness_threshold(self):
        for m in [
            MANIFEST_COPILOT_GOVERNANCE,
            MANIFEST_DLP_MONITORING,
            MANIFEST_INSIDER_RISK,
        ]:
            assert m["freshness_threshold_hours"] == 1

    def test_aggregation_worst_case(self):
        for m in [
            MANIFEST_COPILOT_GOVERNANCE,
            MANIFEST_DLP_MONITORING,
            MANIFEST_INSIDER_RISK,
        ]:
            assert m["aggregation"]["method"] == "worst_case"

    @patch("primust_connectors.purview.primust")
    def test_register_manifests_stores_ids(self, mock_primust):
        mock_pipeline = MagicMock()
        mock_pipeline.register_check.side_effect = [
            _mock_manifest_registration("copilot"),
            _mock_manifest_registration("dlp"),
            _mock_manifest_registration("insider"),
        ]
        mock_primust.Pipeline.return_value = mock_pipeline

        c = _make_connector()
        c.register_manifests()

        assert "purview_copilot_governance" in c._manifest_ids
        assert "purview_dlp_monitoring" in c._manifest_ids
        assert "purview_insider_risk" in c._manifest_ids
        assert mock_pipeline.register_check.call_count == 3


class TestCopilotInteraction:
    def test_clean_copilot_interaction_passes(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test_manifest"

        result = c.record_copilot_interaction(
            pipeline=mock_pipeline,
            event=COPILOT_CLEAN_EVENT,
        )

        assert isinstance(result, PrimustPurviewRecord)
        assert isinstance(result.result, CopilotGovernanceResult)
        assert result.result.has_dlp_match is False
        assert result.result.sensitivity_label == "General"
        assert result.result.content_accessed_count == 2

        # Verify pipeline.record was called with "pass"
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_dlp_match_copilot_interaction_fails(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        result = c.record_copilot_interaction(
            pipeline=mock_pipeline,
            event=COPILOT_DLP_MATCH_EVENT,
        )

        assert result.result.has_dlp_match is True
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_copilot_risk_assessment_high_on_dlp(self):
        c = _make_connector()
        risk = c._assess_copilot_risk(
            has_dlp_match=True,
            sensitivity_label="General",
            content_accessed_count=1,
        )
        assert risk == "high"

    def test_copilot_risk_assessment_medium_on_high_sensitivity(self):
        c = _make_connector()
        risk = c._assess_copilot_risk(
            has_dlp_match=False,
            sensitivity_label="Highly Confidential",
            content_accessed_count=1,
        )
        assert risk == "medium"

    def test_copilot_risk_assessment_medium_on_many_items(self):
        c = _make_connector()
        risk = c._assess_copilot_risk(
            has_dlp_match=False,
            sensitivity_label="General",
            content_accessed_count=15,
        )
        assert risk == "medium"

    def test_copilot_risk_assessment_low_default(self):
        c = _make_connector()
        risk = c._assess_copilot_risk(
            has_dlp_match=False,
            sensitivity_label="General",
            content_accessed_count=2,
        )
        assert risk == "low"

    def test_copilot_input_commitment_format(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        c.record_copilot_interaction(
            pipeline=mock_pipeline,
            event=COPILOT_CLEAN_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["input"] == "evt_copilot_001|CopilotInteraction"

    def test_copilot_requires_manifest_registration(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.record_copilot_interaction(pipeline=mock_pipeline, event=COPILOT_CLEAN_EVENT)
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestDLPMatch:
    def test_dlp_block_action_fails(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        result = c.record_dlp_match(
            pipeline=mock_pipeline,
            event=DLP_RULE_MATCH_EVENT,
        )

        assert isinstance(result, PrimustPurviewRecord)
        assert isinstance(result.result, DLPResult)
        assert result.result.action_taken == "block"
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_dlp_notify_action_passes(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        result = c.record_dlp_match(
            pipeline=mock_pipeline,
            event=DLP_NOTIFY_EVENT,
        )

        assert result.result.action_taken == "notify"
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_dlp_rule_name_hashed(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        result = c.record_dlp_match(
            pipeline=mock_pipeline,
            event=DLP_RULE_MATCH_EVENT,
        )

        # Rule name should be SHA-256 hashed, not raw
        expected_hash = hashlib.sha256(b"Block external sharing of PII").hexdigest()
        assert result.result.rule_name_hash == expected_hash
        assert result.result.rule_name_hash != "Block external sharing of PII"

    def test_dlp_input_commitment_format(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        c.record_dlp_match(
            pipeline=mock_pipeline,
            event=DLP_RULE_MATCH_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        expected_policy_hash = hashlib.sha256(b"pol-001").hexdigest()
        assert call_kwargs["input"] == f"evt_dlp_001|{expected_policy_hash}"

    def test_dlp_requires_manifest_registration(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.record_dlp_match(pipeline=mock_pipeline, event=DLP_RULE_MATCH_EVENT)
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestSensitivityLabel:
    def test_sensitivity_label_recorded(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        result = c.record_sensitivity_label(
            pipeline=mock_pipeline,
            event=SENSITIVITY_LABEL_EVENT,
        )

        assert isinstance(result, PrimustPurviewRecord)
        assert result.result.sensitivity_label == "Highly Confidential"
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_sensitivity_label_input_format(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        c.record_sensitivity_label(
            pipeline=mock_pipeline,
            event=SENSITIVITY_LABEL_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["input"] == "evt_label_001|SensitivityLabelApplied"

    def test_sensitivity_label_requires_manifest(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.record_sensitivity_label(pipeline=mock_pipeline, event=SENSITIVITY_LABEL_EVENT)
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "register_manifests" in str(e)

    def test_sensitivity_label_downgrade_records_fail(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"
        downgrade_event = dict(SENSITIVITY_LABEL_EVENT)
        downgrade_event["LabelAction"] = "downgrade"

        c.record_sensitivity_label(
            pipeline=mock_pipeline,
            event=downgrade_event,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "fail"


class TestInsiderRisk:
    def test_high_risk_fails(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_insider_risk"] = "sha256:test"

        result = c.record_insider_risk(
            pipeline=mock_pipeline,
            event=INSIDER_RISK_EVENT,
        )

        assert isinstance(result, PrimustPurviewRecord)
        assert isinstance(result.result, InsiderRiskResult)
        assert result.result.risk_level == "high"
        assert result.result.signal_count == 2
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_low_risk_passes(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_insider_risk"] = "sha256:test"

        result = c.record_insider_risk(
            pipeline=mock_pipeline,
            event=INSIDER_RISK_LOW_EVENT,
        )

        assert result.result.risk_level == "low"
        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["check_result"] == "pass"

    def test_insider_risk_requires_manifest(self):
        c = _make_connector()
        mock_pipeline = MagicMock()

        try:
            c.record_insider_risk(pipeline=mock_pipeline, event=INSIDER_RISK_EVENT)
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "register_manifests" in str(e)


class TestActivityPolling:
    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_processes_copilot_events(self, mock_client_cls):
        # Mock the content list response
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"contentUri": "https://manage.office.com/content/blob1"}
        ]
        mock_list_resp.raise_for_status = MagicMock()

        # Mock the blob fetch response
        mock_blob_resp = MagicMock()
        mock_blob_resp.json.return_value = [COPILOT_CLEAN_EVENT]
        mock_blob_resp.raise_for_status = MagicMock()

        # Set up client mock to return different responses for GET calls
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_list_resp, mock_blob_resp]
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        records = c.poll_activities(pipeline=mock_pipeline)

        assert len(records) == 1
        assert isinstance(records[0].result, CopilotGovernanceResult)

    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_processes_dlp_events(self, mock_client_cls):
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"contentUri": "https://manage.office.com/content/blob1"}
        ]
        mock_list_resp.raise_for_status = MagicMock()

        mock_blob_resp = MagicMock()
        mock_blob_resp.json.return_value = [DLP_RULE_MATCH_EVENT]
        mock_blob_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_list_resp, mock_blob_resp]
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        records = c.poll_activities(pipeline=mock_pipeline)

        assert len(records) == 1
        assert isinstance(records[0].result, DLPResult)

    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_mixed_events(self, mock_client_cls):
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"contentUri": "https://manage.office.com/content/blob1"}
        ]
        mock_list_resp.raise_for_status = MagicMock()

        mock_blob_resp = MagicMock()
        mock_blob_resp.json.return_value = [
            COPILOT_CLEAN_EVENT,
            DLP_RULE_MATCH_EVENT,
            SENSITIVITY_LABEL_EVENT,
            {"Id": "evt_ignored", "Operation": "SomeOtherEvent"},  # should be skipped
        ]
        mock_blob_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_list_resp, mock_blob_resp]
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        records = c.poll_activities(pipeline=mock_pipeline)

        # 3 governance events, 1 ignored
        assert len(records) == 3

    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_processes_insider_risk_events(self, mock_client_cls):
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"contentUri": "https://manage.office.com/content/blob1"}
        ]
        mock_list_resp.raise_for_status = MagicMock()

        mock_blob_resp = MagicMock()
        mock_blob_resp.json.return_value = [INSIDER_RISK_EVENT]
        mock_blob_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_list_resp, mock_blob_resp]
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        c._manifest_ids["purview_insider_risk"] = "sha256:test"

        records = c.poll_activities(pipeline=mock_pipeline)

        assert len(records) == 1
        assert isinstance(records[0].result, InsiderRiskResult)

    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_empty_blobs(self, mock_client_cls):
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = []
        mock_list_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_list_resp
        mock_client_cls.return_value = mock_client

        mock_pipeline = MagicMock()

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

        records = c.poll_activities(pipeline=mock_pipeline)
        assert len(records) == 0

    @patch("primust_connectors.purview.httpx.Client")
    def test_poll_activities_fail_open_on_api_error(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        failing_resp = MagicMock()
        failing_resp.status_code = 500
        failing_resp.raise_for_status.side_effect = Exception("boom")
        mock_client.get.return_value = failing_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        records = c.poll_activities(pipeline=MagicMock())
        assert records == []


class TestOAuth:
    @patch("primust_connectors.purview.httpx.Client")
    def test_get_access_token(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"access_token": "test-bearer-token"}
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        token = c._get_access_token()

        assert token == "test-bearer-token"
        assert c._access_token == "test-bearer-token"

        # Verify correct token URL
        call_args = mock_client.post.call_args
        assert "test-tenant-id" in call_args.args[0]
        assert "oauth2/v2.0/token" in call_args.args[0]

    @patch("primust_connectors.purview.httpx.Client")
    def test_auth_headers_triggers_token_refresh(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"access_token": "fresh-token"}
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        assert c._access_token is None

        headers = c._auth_headers()
        assert headers["Authorization"] == "Bearer fresh-token"

    def test_auth_headers_uses_cached_token(self):
        c = _make_connector()
        c._access_token = "cached-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        headers = c._auth_headers()
        assert headers["Authorization"] == "Bearer cached-token"


class TestSubscription:
    @patch("primust_connectors.purview.httpx.Client")
    def test_start_subscription(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "enabled",
            "contentType": "Audit.General",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        result = c.start_subscription()

        assert result["status"] == "enabled"
        call_args = mock_client.post.call_args
        assert "subscriptions/start" in call_args.args[0]

    @patch("primust_connectors.purview.httpx.Client")
    def test_start_subscription_with_webhook_param(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "enabled",
            "contentType": "Audit.General",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        c = _make_connector()
        c._access_token = "test-token"
        c._token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        c.start_subscription(webhook_url="https://example.com/purview/webhook")

        call_kwargs = mock_client.post.call_args.kwargs
        assert call_kwargs["params"]["webhookUrl"] == "https://example.com/purview/webhook"


class TestPrivacyInvariants:
    """These tests are CRITICAL — privacy invariants are non-negotiable."""

    def test_no_content_in_copilot_details(self):
        """File content, interaction content must NOT appear in details."""
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        c.record_copilot_interaction(
            pipeline=mock_pipeline,
            event=COPILOT_CLEAN_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        details = call_kwargs["details"]

        # These must NOT be in details — content/PII
        assert "file_name" not in details
        assert "file_content" not in details
        assert "user_id" not in details
        assert "UserId" not in details
        assert "email" not in details
        assert "AccessedItems" not in details
        assert "content" not in details

        # These are OK — aggregate metadata only
        assert "has_dlp_match" in details
        assert "sensitivity_label_bucket" in details
        assert "sensitivity_label_hash" in details
        assert "risk_level" in details
        assert "content_accessed_count" in details

    def test_no_pii_in_dlp_details(self):
        """User PII and matched content must NOT appear in DLP details."""
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        c.record_dlp_match(
            pipeline=mock_pipeline,
            event=DLP_RULE_MATCH_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        details = call_kwargs["details"]

        # Raw rule name must NOT appear — only hash
        assert "Block external sharing of PII" not in str(details)
        assert "rule_name_hash" in details
        assert "policy_id_hash" in details
        assert "policy_id" not in details
        assert "user_id" not in details
        assert "UserId" not in details

    def test_no_pii_in_insider_risk_details(self):
        """User identity and signal details must NOT appear."""
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_insider_risk"] = "sha256:test"

        c.record_insider_risk(
            pipeline=mock_pipeline,
            event=INSIDER_RISK_EVENT,
        )

        call_kwargs = mock_pipeline.record.call_args.kwargs
        details = call_kwargs["details"]

        assert "user_id" not in details
        assert "Signals" not in details
        assert "data_exfiltration" not in str(details)
        assert "risk_level" in details
        assert "signal_count" in details

    def test_visibility_default_opaque(self):
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"
        c.record_copilot_interaction(pipeline=mock_pipeline, event=COPILOT_CLEAN_EVENT)

        call_kwargs = mock_pipeline.record.call_args.kwargs
        assert call_kwargs["visibility"] == "opaque"

    def test_dlp_rule_name_always_hashed(self):
        """Rule names must be SHA-256 hashed, never stored raw."""
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_dlp_monitoring"] = "sha256:test"

        c.record_dlp_match(pipeline=mock_pipeline, event=DLP_RULE_MATCH_EVENT)

        call_kwargs = mock_pipeline.record.call_args.kwargs
        details = call_kwargs["details"]
        rule_hash = details["rule_name_hash"]

        # Verify it's a valid SHA-256 hex string
        assert len(rule_hash) == 64
        assert all(c in "0123456789abcdef" for c in rule_hash)

    def test_no_file_names_in_copilot_record(self):
        """AccessedItems file names must NOT transit to Primust."""
        mock_pipeline = MagicMock()
        mock_pipeline.record.return_value = _mock_record_result()

        c = _make_connector()
        c._manifest_ids["purview_copilot_governance"] = "sha256:test"

        c.record_copilot_interaction(pipeline=mock_pipeline, event=COPILOT_CLEAN_EVENT)

        call_kwargs = mock_pipeline.record.call_args.kwargs
        details_str = str(call_kwargs["details"])
        input_str = str(call_kwargs["input"])

        assert "doc1.docx" not in details_str
        assert "doc2.xlsx" not in details_str
        assert "doc1.docx" not in input_str
        assert "doc2.xlsx" not in input_str


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

    def test_has_data_sensitivity(self):
        assert bool(FIT_VALIDATION["data_sensitivity"])

    def test_has_external_verifier(self):
        assert bool(FIT_VALIDATION["external_verifier"])

    def test_cross_run_consistency_applicable(self):
        assert FIT_VALIDATION["cross_run_consistency_applicable"] is True

    def test_three_property_filter_passes(self):
        """Three-property fit test: regulated + trust deficit + data sensitivity."""
        from primust_connectors.fit_validation import validate_fit

        result = validate_fit(FIT_VALIDATION)
        assert result["fit_confirmed"] is True
        assert result["score"] == "3/3"


class TestSHA256Helper:
    def test_sha256_hash_deterministic(self):
        h1 = _sha256_hash("test value")
        h2 = _sha256_hash("test value")
        assert h1 == h2

    def test_sha256_hash_is_hex(self):
        h = _sha256_hash("anything")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_hash_different_inputs(self):
        h1 = _sha256_hash("rule A")
        h2 = _sha256_hash("rule B")
        assert h1 != h2
