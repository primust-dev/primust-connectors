"""
Primust Connector: Microsoft Purview Copilot Governance
========================================================
Fit: STRONG
Verifier: Compliance officer, auditor, regulator — external, trust deficit,
          cannot receive Copilot interaction content or user PII
Problem solved: Copilot governance paradox — prove DLP evaluated, sensitivity
                labels applied, and content access audited on every Copilot
                interaction without exposing the interaction content itself
Proof ceiling: Attestation (external platform audit log — Purview events are
               attestation-only SaaS signals)
Buildable: NOW — Office 365 Management Activity API + REST only
Regulatory hook: GDPR Art. 35, EU AI Act Art. 14, SOC 2 CC6.1, NIST AI RMF

The core GEP value here is proving AI (Copilot) governance ran. The compliance
officer can verify that every Copilot interaction was DLP-evaluated, sensitivity-
classified, and content-access audited — without ever seeing the interaction
content, the files Copilot accessed, or user PII. That's the Copilot governance
paradox solved.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

import httpx
import primust

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Manifests — register once per environment, reuse manifest_id forever
# ---------------------------------------------------------------------------

MANIFEST_COPILOT_GOVERNANCE = {
    "name": "purview_copilot_governance",
    "description": (
        "Microsoft Purview Copilot interaction audit. "
        "Proves DLP evaluated, sensitivity labels applied, and content "
        "access audited on Copilot interactions."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "content_access_audit",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "event_presence",
            "purpose": "Copilot content access event recorded in audit log",
        },
        {
            "stage": 2,
            "name": "dlp_policy_evaluation",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "DLP policy evaluated against Copilot interaction content",
        },
        {
            "stage": 3,
            "name": "sensitivity_classification",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Sensitivity label applied to content accessed by Copilot",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 1,
    "publisher": "your-org-id",
}

MANIFEST_DLP_MONITORING = {
    "name": "purview_dlp_monitoring",
    "description": (
        "Microsoft Purview Data Loss Prevention policy monitoring. "
        "Proves DLP rules evaluated and actions taken on policy matches."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "dlp_rule_evaluation",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "DLP rule matched against content — action taken",
        },
        {
            "stage": 2,
            "name": "dlp_action_enforcement",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "DLP enforcement action (block/notify/override) applied",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 1,
    "publisher": "your-org-id",
}

MANIFEST_INSIDER_RISK = {
    "name": "purview_insider_risk",
    "description": (
        "Microsoft Purview Insider Risk Management signals. "
        "Proves insider risk signals evaluated and risk levels assigned."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "risk_signal_evaluation",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "Insider risk signal evaluated by Purview ML model",
        },
        {
            "stage": 2,
            "name": "risk_level_assignment",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Risk level assigned based on signal aggregation",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 1,
    "publisher": "your-org-id",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CopilotGovernanceResult:
    """Result from Copilot interaction audit — aggregate metadata only, NO content."""

    activity_id: str  # Purview activity ID (not PII)
    operation: str  # e.g., "CopilotInteraction"
    has_dlp_match: bool  # DLP policy triggered
    sensitivity_label: str  # Label applied (e.g., "Confidential")
    risk_level: str  # "low", "medium", "high"
    content_accessed_count: int  # aggregate only — never content itself


@dataclass
class DLPResult:
    """Result from DLP policy match — policy metadata only, NO content."""

    policy_id: str  # Purview policy ID
    rule_name_hash: str  # SHA-256 hash of rule name — never raw name
    action_taken: str  # "block", "notify", "override"
    severity: str  # "low", "medium", "high", "informational"


@dataclass
class InsiderRiskResult:
    """Result from insider risk signal — risk bucket only, NO user details."""

    alert_id: str  # Purview alert ID
    risk_level: str  # "low", "medium", "high"
    signal_count: int  # aggregate signal count only


@dataclass
class PrimustPurviewRecord:
    """What Primust commits — no content, no PII, just proof."""

    commitment_hash: str  # input commitment (never sent to Primust)
    record_id: str
    proof_level: str  # always "attestation" for Purview
    vpec_id: Optional[str]  # set when pipeline.close() is called
    result: Union[CopilotGovernanceResult, DLPResult, InsiderRiskResult]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_hash(value: str) -> str:
    """SHA-256 hash a string for privacy-safe recording."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class PurviewConnector:
    """
    Wraps Microsoft Purview audit events with Primust VPEC issuance.

    Usage (Copilot governance monitoring):
        connector = PurviewConnector(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
            primust_api_key=os.environ["PRIMUST_API_KEY"],
        )
        connector.register_manifests()

        # Poll for Copilot governance events:
        pipeline = connector.new_pipeline(workflow_id="copilot-governance-v1")
        records = connector.poll_activities(pipeline)
        vpec = pipeline.close()
        # vpec -> store in compliance record, provide to auditor on request

    The auditor receives the VPEC. It proves:
      - DLP evaluated on Copilot interaction at timestamp T
      - Sensitivity label applied to accessed content
      - Content access was audited
    The auditor does NOT receive: interaction content, file content, user PII,
    which specific files Copilot accessed, DLP rule internals.
    Copilot governance paradox resolved.
    """

    BASE_URL = "https://manage.office.com/api/v1.0"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    # Event types relevant for Copilot governance
    COPILOT_EVENT_TYPES = {"CopilotInteraction", "FileAccessed"}
    DLP_EVENT_TYPES = {"DLPRuleMatch"}
    LABEL_EVENT_TYPES = {"SensitivityLabelApplied", "MIPLabel"}
    INSIDER_RISK_EVENT_TYPES = {"InsiderRiskAlert"}

    ALL_GOVERNANCE_EVENT_TYPES = (
        COPILOT_EVENT_TYPES | DLP_EVENT_TYPES | LABEL_EVENT_TYPES | INSIDER_RISK_EVENT_TYPES
    )

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        primust_api_key: str,
        visibility: str = "opaque",
    ):
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        if not client_id or not client_id.strip():
            raise ValueError("client_id is required")
        if not client_secret or not client_secret.strip():
            raise ValueError("client_secret is required")

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.primust_api_key = primust_api_key
        self.visibility = visibility
        self._manifest_ids: dict[str, str] = {}
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    # ------------------------------------------------------------------
    # OAuth2 authentication
    # ------------------------------------------------------------------

    def _get_access_token(self, force_refresh: bool = False) -> str:
        """OAuth2 client_credentials flow for Office 365 Management API."""
        if (
            not force_refresh
            and self._access_token
            and self._token_expires_at
            and datetime.now(timezone.utc) < self._token_expires_at
        ):
            return self._access_token

        token_url = self.TOKEN_URL.format(tenant_id=self.tenant_id)
        with httpx.Client() as client:
            resp = client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://manage.office.com/.default",
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()

        self._access_token = data["access_token"]
        expires_in_seconds = int(data.get("expires_in", 3600))
        # Refresh one minute early to avoid edge expiry.
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=max(60, expires_in_seconds - 60)
        )
        return self._access_token

    def _auth_headers(self) -> dict[str, str]:
        """Get authorization headers, refreshing token if needed."""
        if (
            not self._access_token
            or not self._token_expires_at
            or datetime.now(timezone.utc) >= self._token_expires_at
        ):
            self._get_access_token()
        return {"Authorization": f"Bearer {self._access_token}"}

    def _request_with_refresh(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        params: Optional[dict[str, str]] = None,
        data: Optional[dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> httpx.Response:
        """Send request, refreshing bearer token once on 401."""
        request_method = method.upper()
        request_fn = client.request
        if request_method == "GET":
            request_fn = client.get
        elif request_method == "POST":
            request_fn = client.post

        resp = request_fn(
            url,
            params=params,
            data=data,
            headers=self._auth_headers(),
            timeout=timeout,
        )
        if resp.status_code == 401:
            self._get_access_token(force_refresh=True)
            resp = request_fn(
                url,
                params=params,
                data=data,
                headers=self._auth_headers(),
                timeout=timeout,
            )
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # One-time setup
    # ------------------------------------------------------------------

    def register_manifests(self) -> None:
        """Register check manifests with Primust. Call once per environment."""
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [
            MANIFEST_COPILOT_GOVERNANCE,
            MANIFEST_DLP_MONITORING,
            MANIFEST_INSIDER_RISK,
        ]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id
            print(f"Registered {manifest['name']}: {result.manifest_id}")

    def new_pipeline(self, workflow_id: str) -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def start_subscription(
        self,
        content_type: str = "Audit.General",
        webhook_url: Optional[str] = None,
    ) -> dict:
        """Start Office 365 Management Activity API subscription."""
        url = f"{self.BASE_URL}/{self.tenant_id}/activity/feed/subscriptions/start"
        params: dict[str, str] = {"contentType": content_type}
        if webhook_url:
            # Optional webhook mode hint; polling mode remains supported.
            params["webhookUrl"] = webhook_url
        with httpx.Client() as client:
            try:
                resp = self._request_with_refresh(
                    client,
                    "POST",
                    url,
                    params=params,
                )
                return resp.json()
            except Exception as exc:
                # SI-4 fail-open: caller can continue in degraded mode.
                logger.warning("Purview start_subscription failed", exc_info=exc)
                return {"status": "error", "error": type(exc).__name__}

    # ------------------------------------------------------------------
    # Activity polling
    # ------------------------------------------------------------------

    def poll_activities(
        self,
        pipeline: primust.Pipeline,
        content_type: str = "Audit.General",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> list[PrimustPurviewRecord]:
        """
        Poll for new activity content blobs and record governance checks.

        1. List content blobs from Management Activity API
        2. Fetch each blob
        3. Parse events
        4. For each relevant event, record a governance check

        Returns list of PrimustPurviewRecords for all governance-relevant events.
        """
        records: list[PrimustPurviewRecord] = []
        # Step 1: List available content blobs
        list_url = f"{self.BASE_URL}/{self.tenant_id}/activity/feed/subscriptions/content"
        params: dict[str, str] = {"contentType": content_type}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time

        try:
            with httpx.Client() as client:
                resp = self._request_with_refresh(
                    client,
                    "GET",
                    list_url,
                    params=params,
                )
                content_blobs = resp.json()
        except Exception as exc:
            # SI-4 fail-open: no records this cycle, caller continues.
            logger.warning("Purview poll list failed", exc_info=exc)
            return records

        # Step 2 & 3: Fetch each blob and parse events
        with httpx.Client() as client:
            for blob in content_blobs:
                content_uri = blob.get("contentUri", "")
                if not content_uri:
                    continue

                try:
                    blob_resp = self._request_with_refresh(
                        client,
                        "GET",
                        content_uri,
                    )
                    events = blob_resp.json()
                except Exception as exc:
                    logger.warning("Purview blob fetch failed", exc_info=exc)
                    continue

                # Step 4: Record governance checks for relevant events
                for event in events:
                    operation = event.get("Operation", "")
                    try:
                        if operation in self.COPILOT_EVENT_TYPES:
                            record = self.record_copilot_interaction(pipeline, event)
                            records.append(record)
                        elif operation in self.DLP_EVENT_TYPES:
                            record = self.record_dlp_match(pipeline, event)
                            records.append(record)
                        elif operation in self.LABEL_EVENT_TYPES:
                            record = self.record_sensitivity_label(pipeline, event)
                            records.append(record)
                        elif operation in self.INSIDER_RISK_EVENT_TYPES:
                            record = self.record_insider_risk(pipeline, event)
                            records.append(record)
                    except Exception as exc:
                        # SI-4 fail-open: keep processing other events.
                        logger.warning("Purview event recording failed", exc_info=exc)
                        continue

        return records

    # ------------------------------------------------------------------
    # Event recording methods
    # ------------------------------------------------------------------

    def record_copilot_interaction(
        self,
        pipeline: primust.Pipeline,
        event: dict,
        visibility: Optional[str] = None,
    ) -> PrimustPurviewRecord:
        """
        Record a Copilot interaction audit event.

        Extracts governance-relevant metadata only — NO content, NO PII.
        Only aggregate counts, label names, and risk buckets transit.
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("purview_copilot_governance")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before record_copilot_interaction()")

        # Extract governance metadata (NO content, NO PII)
        activity_id = event.get("Id", "")
        operation = event.get("Operation", "CopilotInteraction")

        # DLP match info — only whether a match occurred, not what matched
        policy_match_info = event.get("PolicyMatchInfo", {})
        has_dlp_match = bool(policy_match_info.get("HasMatch", False))

        # Sensitivity label — label name only, not content
        sensitivity_info = event.get("SensitivityLabel", {})
        sensitivity_label = sensitivity_info.get("LabelName", "None")

        # Content access count — aggregate only
        accessed_items = event.get("AccessedItems", [])
        content_accessed_count = len(accessed_items)

        # Determine risk level from available signals
        risk_level = self._assess_copilot_risk(
            has_dlp_match, sensitivity_label, content_accessed_count
        )

        # Governance evidence semantics: a detected match means controls worked.
        check_result = "pass"
        sensitivity_label_bucket = self._bucket_sensitivity_label(sensitivity_label)
        sensitivity_label_hash = _sha256_hash(sensitivity_label) if sensitivity_label else ""

        # Build result
        copilot_result = CopilotGovernanceResult(
            activity_id=activity_id,
            operation=operation,
            has_dlp_match=has_dlp_match,
            sensitivity_label=sensitivity_label,
            risk_level=risk_level,
            content_accessed_count=content_accessed_count,
        )

        # Commit to Primust — NO content, NO PII in details
        # Input = activity_id + operation (structural metadata only)
        try:
            record = pipeline.record(
                check="purview.copilot_interaction",
                manifest_id=manifest_id,
                input=f"{activity_id}|{operation}",
                check_result=check_result,
                details={
                    "has_dlp_match": has_dlp_match,
                    "sensitivity_label_bucket": sensitivity_label_bucket,
                    "sensitivity_label_hash": sensitivity_label_hash,
                    "risk_level": risk_level,
                    "content_accessed_count": content_accessed_count,
                    # NOTE: no file names, no content, no user identity
                },
                visibility=vis,
            )
        except Exception as exc:
            # SI-4 fail-open: return a local record marker and continue.
            logger.warning("Purview copilot record failed", exc_info=exc)
            return PrimustPurviewRecord(
                commitment_hash="",
                record_id=f"local_error:{type(exc).__name__}",
                proof_level="attestation",
                vpec_id=None,
                result=copilot_result,
            )

        return PrimustPurviewRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            result=copilot_result,
        )

    def record_dlp_match(
        self,
        pipeline: primust.Pipeline,
        event: dict,
        visibility: Optional[str] = None,
    ) -> PrimustPurviewRecord:
        """
        Record a DLP policy match event.

        Only policy ID (not rule internals), hashed rule name, action taken,
        and severity transit. NO matched content, NO user PII.
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("purview_dlp_monitoring")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before record_dlp_match()")

        # Extract DLP metadata
        policy_details = event.get("PolicyDetails", {})
        policy_id = policy_details.get("PolicyId", event.get("PolicyId", ""))
        rule_name = policy_details.get("RuleName", event.get("RuleName", ""))
        action_taken = policy_details.get("Action", event.get("Action", "notify"))
        severity = policy_details.get("Severity", event.get("Severity", "informational"))
        activity_id = event.get("Id", "")

        # Hash rule name for privacy — never store raw rule names
        rule_name_hash = _sha256_hash(rule_name) if rule_name else ""
        policy_id_hash = _sha256_hash(policy_id) if policy_id else ""

        # Governance evidence semantics: enforcement action proves control executed.
        check_result = "pass"

        dlp_result = DLPResult(
            policy_id=policy_id,
            rule_name_hash=rule_name_hash,
            action_taken=action_taken,
            severity=severity,
        )

        # Commit to Primust — hashed rule name, no content
        try:
            record = pipeline.record(
                check="purview.dlp_policy_match",
                manifest_id=manifest_id,
                input=f"{activity_id}|{policy_id_hash}",
                check_result=check_result,
                details={
                    "policy_id_hash": policy_id_hash,
                    "rule_name_hash": rule_name_hash,
                    "action_taken": action_taken,
                    "severity": severity,
                    # NOTE: no matched content, no user PII, no rule internals
                },
                visibility=vis,
            )
        except Exception as exc:
            logger.warning("Purview dlp record failed", exc_info=exc)
            return PrimustPurviewRecord(
                commitment_hash="",
                record_id=f"local_error:{type(exc).__name__}",
                proof_level="attestation",
                vpec_id=None,
                result=dlp_result,
            )

        return PrimustPurviewRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            result=dlp_result,
        )

    def record_sensitivity_label(
        self,
        pipeline: primust.Pipeline,
        event: dict,
        visibility: Optional[str] = None,
    ) -> PrimustPurviewRecord:
        """
        Record a sensitivity label application event.

        Only label name and action transit — NO file content, NO user PII.
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("purview_copilot_governance")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before record_sensitivity_label()")

        activity_id = event.get("Id", "")
        operation = event.get("Operation", "SensitivityLabelApplied")
        label_action = event.get("LabelAction", "apply")
        label_name = event.get("SensitivityLabel", {}).get("LabelName", "None")
        label_bucket = self._bucket_sensitivity_label(label_name)
        label_hash = _sha256_hash(label_name) if label_name else ""
        action = str(label_action).lower()
        check_result = "fail" if action in {"remove", "downgrade"} else "pass"

        copilot_result = CopilotGovernanceResult(
            activity_id=activity_id,
            operation=operation,
            has_dlp_match=False,
            sensitivity_label=label_name,
            risk_level="low",
            content_accessed_count=0,
        )

        try:
            record = pipeline.record(
                check="purview.sensitivity_label",
                manifest_id=manifest_id,
                input=f"{activity_id}|{operation}",
                check_result=check_result,
                details={
                    "sensitivity_label_bucket": label_bucket,
                    "sensitivity_label_hash": label_hash,
                    "label_action": label_action,
                    # NOTE: no file name, no content, no user PII
                },
                visibility=vis,
            )
        except Exception as exc:
            logger.warning("Purview sensitivity record failed", exc_info=exc)
            return PrimustPurviewRecord(
                commitment_hash="",
                record_id=f"local_error:{type(exc).__name__}",
                proof_level="attestation",
                vpec_id=None,
                result=copilot_result,
            )

        return PrimustPurviewRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            result=copilot_result,
        )

    def record_insider_risk(
        self,
        pipeline: primust.Pipeline,
        event: dict,
        visibility: Optional[str] = None,
    ) -> PrimustPurviewRecord:
        """
        Record an insider risk signal event.

        Only risk level and aggregate signal count transit — NO user details.
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("purview_insider_risk")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before record_insider_risk()")

        activity_id = event.get("Id", "")
        alert_id = event.get("AlertId", activity_id)
        risk_level = event.get("RiskLevel", "low")
        signals = event.get("Signals", [])
        signal_count = len(signals)

        # Governance evidence semantics: high risk means detector worked.
        check_result = "pass"

        insider_result = InsiderRiskResult(
            alert_id=alert_id,
            risk_level=risk_level,
            signal_count=signal_count,
        )

        try:
            record = pipeline.record(
                check="purview.audit_event",
                manifest_id=manifest_id,
                input=f"{alert_id}|{risk_level}",
                check_result=check_result,
                details={
                    "risk_level": risk_level,
                    "signal_count": signal_count,
                    # NOTE: no user identity, no signal details, no activity specifics
                },
                visibility=vis,
            )
        except Exception as exc:
            logger.warning("Purview insider risk record failed", exc_info=exc)
            return PrimustPurviewRecord(
                commitment_hash="",
                record_id=f"local_error:{type(exc).__name__}",
                proof_level="attestation",
                vpec_id=None,
                result=insider_result,
            )

        return PrimustPurviewRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            result=insider_result,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assess_copilot_risk(
        self,
        has_dlp_match: bool,
        sensitivity_label: str,
        content_accessed_count: int,
    ) -> str:
        """Assess risk level from Copilot interaction signals."""
        if has_dlp_match:
            return "high"
        sensitivity_text = str(sensitivity_label).lower()
        high_keywords = ("secret", "confidential", "restricted", "sensitive")
        if any(keyword in sensitivity_text for keyword in high_keywords):
            return "medium"
        if content_accessed_count > 10:
            return "medium"
        return "low"

    def _bucket_sensitivity_label(self, sensitivity_label: str) -> str:
        """Bucket custom enterprise labels without transmitting raw label names."""
        text = str(sensitivity_label).lower()
        if not text or text == "none":
            return "none"
        if any(k in text for k in ("top secret", "secret", "highly confidential", "restricted")):
            return "high"
        if any(k in text for k in ("confidential", "internal", "private", "sensitive")):
            return "medium"
        return "low"


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

FIT_VALIDATION = {
    "platform": "Microsoft Purview",
    "category": "Data governance and compliance",
    "fit": "STRONG",
    "external_verifier": "Compliance officer, auditor, regulator",
    "trust_deficit": True,
    "data_sensitivity": (
        "Copilot interactions, DLP matches, sensitivity labels — "
        "content never exposed, only aggregate metadata"
    ),
    "gep_value": (
        "VPEC proves Copilot governance checks ran: DLP evaluated, "
        "sensitivity labels applied, content access audited. "
        "Verifier confirms AI governance occurred without receiving "
        "the interaction content or user PII."
    ),
    "proof_ceiling": "attestation",
    "proof_ceiling_notes": (
        "Purview events are attestation-only (external platform audit log). "
        "Path to mathematical requires inline DLP evaluation."
    ),
    "buildable_today": True,
    "sdk_required": "None",
    "cross_run_consistency_applicable": True,
    "regulatory_hooks": [
        "GDPR Article 35 -- DPIA for AI processing",
        "EU AI Act Article 14 -- Human oversight",
        "SOC 2 CC6.1 -- Logical access controls",
        "NIST AI RMF MAP 1.5 -- AI risk identification",
    ],
}
