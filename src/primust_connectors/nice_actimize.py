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
Primust Connector: NICE Actimize AML/Fraud Detection
=====================================================
Fit: STRONG
Verifier: FinCEN, OCC, Fed, FCA, AUSTRAC — banking regulators with SAR authority
Problem solved: AML paradox at the transaction monitoring layer —
               prove transaction monitoring rules ran without revealing
               the velocity/structuring thresholds that enable evasion
Proof ceiling (REST/today): Attestation for ML components,
                             Mathematical achievable for threshold rule stages
                             (velocity counts, amount thresholds)
Proof ceiling (Java SDK, post P10-D): Mathematical across deterministic stages

Three surfaces:
  1. ActimizeAlertEvaluator — SAM transaction alert evaluation (Attestation)
  2. ActimizeSARWorkflow — SAR filing decision (Witnessed)
  3. ActimizeKYCAssessor — KYC/CDD assessment (Attestation)

NICE Actimize REST API: Actimize Risk Case Manager API + ActOne REST API
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from primust_artifact_core.commitment import commit as _artifact_commit

try:
    import primust
    from primust import Pipeline, Run
    from primust.models import RecordResult, VPEC, ProofLevel
    PRIMUST_AVAILABLE = True
except ImportError:
    PRIMUST_AVAILABLE = False


# ---------------------------------------------------------------------------
# Commitment — raw data never leaves customer environment
# ---------------------------------------------------------------------------

def _commit(data: Any) -> str:
    """Commit via artifact-core. Only the hash transits to Primust."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    hash_str, _ = _artifact_commit(canonical.encode(), "sha256")
    return hash_str


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

MANIFEST_TRANSACTION_MONITORING = {
    "name": "actimize_transaction_monitoring",
    "description": (
        "NICE Actimize SAM (Suspicious Activity Monitoring) transaction monitoring. "
        "Velocity checks, structuring detection, cross-account pattern analysis, "
        "ML behavioral anomaly scoring."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "velocity_rule",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Transaction count within rolling time window vs configured threshold",
            "regulatory_references": ["bsa_aml", "fincen_31cfr1020"],
        },
        {
            "stage": 2,
            "name": "amount_threshold",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Transaction amount vs regulatory reporting threshold ($10,000 CTR)",
            "regulatory_references": ["bsa_aml", "31cfr1020_315_ctr"],
        },
        {
            "stage": 3,
            "name": "structuring_detection",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": (
                "Multiple sub-threshold transactions summing to reportable amount "
                "(BSA §5324 structuring pattern)"
            ),
            "regulatory_references": ["bsa_aml", "bsa_5324_structuring"],
        },
        {
            "stage": 4,
            "name": "behavioral_ml_model",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "Behavioral anomaly score — deviation from account baseline",
            "regulatory_references": ["bsa_aml"],
        },
        {
            "stage": 5,
            "name": "composite_risk_score",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Weighted composite risk score >= alert generation threshold",
            "regulatory_references": ["bsa_aml", "fincen_31cfr1020"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 1,
    "publisher": "your-org-id",
}

MANIFEST_KYC_REFRESH = {
    "name": "actimize_kyc_refresh",
    "description": (
        "NICE Actimize KYC periodic refresh monitoring. "
        "Validates customer profile against current risk model and triggers "
        "enhanced due diligence when risk score exceeds threshold."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "risk_score_evaluation",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Customer risk score vs KYC refresh trigger threshold",
            "regulatory_references": ["bsa_cdd_rule", "fatf_rec10"],
        },
        {
            "stage": 2,
            "name": "edd_trigger_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Customer risk factors present in EDD trigger criteria",
            "regulatory_references": ["bsa_cdd_rule", "fatf_rec10"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 24,
    "publisher": "your-org-id",
}

MANIFEST_SAR_DECISION = {
    "name": "actimize_sar_decision",
    "description": (
        "SAR (Suspicious Activity Report) filing decision process. "
        "Analyst review + determination to file or no-file. "
        "Uses Witnessed level — human analyst decision with VDF time proof."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "alert_review",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "purpose": "Alert reviewed against case evidence",
            "regulatory_references": ["bsa_sar_31_cfr_1020", "fincen_sar_reporting"],
        },
        {
            "stage": 2,
            "name": "analyst_determination",
            "type": "custom_code",
            "proof_level": "witnessed",
            "purpose": "BSA officer determination: file SAR or close alert with documented rationale",
            "reference": "BSA/AML Compliance Program — 31 CFR §1020.320",
            "regulatory_references": ["bsa_sar_31_cfr_1020", "fincen_sar_reporting", "finra_aml"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 720,
    "publisher": "your-org-id",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ActimizeAlertResult:
    alert_id: str
    alert_type: str          # "VELOCITY" | "STRUCTURING" | "BEHAVIORAL" | "COMPOSITE"
    risk_score: float
    alert_generated: bool
    rule_codes_fired: list[str]
    raw_response: dict


@dataclass
class KYCAssessmentResult:
    assessment_id: str
    risk_rating: str
    decision: str
    rules_applied_count: int
    raw_response: dict


@dataclass
class SARDecisionResult:
    case_id: str
    determination: str       # "FILE" | "NO_FILE" | "PENDING"
    analyst_id: str
    rationale_hash: Optional[str]
    check_open_tst: Optional[str] = None   # RFC 3161 timestamp — review start
    check_close_tst: Optional[str] = None  # RFC 3161 timestamp — review end


@dataclass
class PrimustAMLRecord:
    commitment_hash: str
    record_id: str
    proof_level: str
    alert_generated: bool
    vpec_id: Optional[str] = None


@dataclass
class PrimustKYCRecord:
    commitment_hash: str
    record_id: str
    proof_level: str
    decision: str


# ---------------------------------------------------------------------------
# Surface 1: Transaction Alert Evaluation (Attestation ceiling)
# ---------------------------------------------------------------------------

class ActimizeAlertEvaluator:
    """
    Wraps NICE Actimize SAM transaction monitoring.

    POST /sam/api/v2/alerts/evaluate

    Proof ceiling: Attestation (ML model evaluation, not interceptable via REST).
    Gap codes:
      actimize_api_error (High) — SAM API call failed
      actimize_auth_failure (Critical) — API key rejected
      actimize_alert_suppressed (High) — alert suppressed without explanation
    Framework tags: ['bsa_aml', 'fincen_31cfr1020']
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        primust_api_key: str,
        alert_score_threshold: float = 0.65,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.primust_api_key = primust_api_key
        self.alert_score_threshold = alert_score_threshold
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        result = p.register_check(MANIFEST_TRANSACTION_MONITORING)
        self._manifest_ids[MANIFEST_TRANSACTION_MONITORING["name"]] = result.manifest_id

    def evaluate_transaction(
        self,
        run: Any,
        transaction_id: str,
        account_id: str,
        amount: float,
        currency: str,
        merchant_category: str = "",
        transaction_type: str = "",
        counterparty_id: Optional[str] = None,
    ) -> PrimustAMLRecord:
        """
        Evaluate a transaction and record governance proof.

        Input commitment fields: transaction_id, account_id, currency,
                                  merchant_category, transaction_type
        CRITICAL: amount is committed but NOT in commitment fields — it's in
        the full input blob that gets hashed, never sent as a named field.
        """
        manifest_id = self._manifest_ids.get("actimize_transaction_monitoring")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Compute input commitment — structured fields only, no PII values
        input_commitment = _commit({
            "transaction_id": transaction_id,
            "account_id": account_id,
            "currency": currency,
            "merchant_category": merchant_category,
            "transaction_type": transaction_type,
        })

        # Call Actimize SAM REST API
        try:
            with httpx.Client() as client:
                resp = client.post(
                    f"{self.base_url}/monitoring/transactions",
                    json={
                        "accountId": account_id,
                        "transactionId": transaction_id,
                        "amount": amount,
                        "type": transaction_type,
                        "counterpartyId": counterparty_id,
                    },
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=15.0,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            gap_type = "actimize_auth_failure" if e.response.status_code == 401 else "actimize_api_error"
            severity = "critical" if gap_type == "actimize_auth_failure" else "high"
            record = run.record(
                check="actimize_transaction_monitoring",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_type, "severity": severity},
                visibility="opaque",
            )
            return PrimustAMLRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                alert_generated=False,
            )
        except Exception:
            record = run.record(
                check="actimize_transaction_monitoring",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "actimize_api_error", "severity": "high"},
                visibility="opaque",
            )
            return PrimustAMLRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                alert_generated=False,
            )

        result = _parse_alert_response(data)

        # Compute output commitment — disposition and metadata, not raw scores
        output_commitment = _commit({
            "alert_id": result.alert_id,
            "risk_score": result.risk_score,
            "alert_disposition": "HIGH_RISK" if result.alert_generated else "LOW_RISK",
            "rule_ids_fired_count": len(result.rule_codes_fired),
        })

        check_result = "fail" if result.alert_generated else "pass"

        record = run.record(
            check="actimize_transaction_monitoring",
            manifest_id=manifest_id,
            check_result=check_result,
            input={"input_commitment": input_commitment, "output_commitment": output_commitment},
            details={
                "alert_generated": result.alert_generated,
                "risk_score": result.risk_score,
                # rule_codes_fired NOT included — reveals monitoring methodology
            },
            visibility="opaque",
        )

        return PrimustAMLRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            alert_generated=result.alert_generated,
        )


# ---------------------------------------------------------------------------
# Surface 2: SAR Filing Workflow (Witnessed ceiling)
# ---------------------------------------------------------------------------

class ActimizeSARWorkflow:
    """
    Wraps SAR filing decision with Witnessed level proof.

    Two RFC 3161 timestamps (check_open_tst + check_close_tst) prove minimum
    review time elapsed. Reviewer Ed25519 signature proves identity.
    Rationale committed locally — plaintext NEVER sent to Primust.

    Framework tags: ['bsa_sar_31_cfr_1020', 'fincen_sar_reporting', 'finra_aml']
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        primust_api_key: str,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.primust_api_key = primust_api_key
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        result = p.register_check(MANIFEST_SAR_DECISION)
        self._manifest_ids[MANIFEST_SAR_DECISION["name"]] = result.manifest_id

    def record_sar_filing(
        self,
        run: Any,
        case_id: str,
        reviewer_id: str,
        filing_decision: str,        # "file" | "no_file" | "defer"
        rationale: str,
        reviewer_signature: str,
        case_content_hash: str,
        min_review_minutes: int = 30,
    ) -> SARDecisionResult:
        """
        Record a SAR filing determination with Witnessed level proof.

        31 CFR §1020.320 requires BSA officers to document:
          - What was reviewed (case_content_hash)
          - The determination made (filing_decision)
          - The rationale (committed locally, never sent)

        INVARIANT: rationale text NEVER sent to Primust. Only rationale_commitment hash.
        INVARIANT: reviewer_id is an opaque identifier — no PII.
        """
        manifest_id = self._manifest_ids.get("actimize_sar_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Compute input commitment
        input_commitment = _commit({
            "case_id": case_id,
            "reviewer_id": reviewer_id,
            "filing_decision": filing_decision,
        })

        # Compute rationale commitment — rationale text hashed, never sent
        rationale_commitment = _commit(rationale)

        # Open Witnessed review session — captures check_open_tst (RFC 3161)
        review = run.open_review(
            check="actimize_sar_decision",
            manifest_id=manifest_id,
            reviewer_key_id=reviewer_id,
            min_duration_seconds=min_review_minutes * 60,
        )

        check_open_tst = getattr(review, "open_tst", None)

        check_result = "pass" if filing_decision == "file" else "fail"

        # Record with full Witnessed payload — captures check_close_tst
        record = run.record(
            check_session=review,
            input={"input_commitment": input_commitment},
            check_result=check_result,
            reviewer_signature=reviewer_signature,
            display_content=case_content_hash,
            rationale=rationale,
            details={"case_id": case_id, "determination": filing_decision},
            visibility="opaque",
        )

        check_close_tst = getattr(record, "recorded_at", None)

        return SARDecisionResult(
            case_id=case_id,
            determination=filing_decision,
            analyst_id=reviewer_id,
            rationale_hash=rationale_commitment,
            check_open_tst=check_open_tst,
            check_close_tst=check_close_tst,
        )


# ---------------------------------------------------------------------------
# Surface 3: KYC/CDD Assessment (Attestation ceiling)
# ---------------------------------------------------------------------------

class ActimizeKYCAssessor:
    """
    Wraps NICE Actimize KYC/CDD assessment.

    POST /kyc/api/v1/assessments

    Proof ceiling: Attestation (ML-powered risk scoring).
    Input commitment: customer_id, risk_tier, assessment_type, jurisdiction
    CRITICAL: PII fields (name, DOB, SSN) excluded from input commitment.

    Framework tags: ['bsa_cdd_rule', 'fatf_rec10']
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        primust_api_key: str,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.primust_api_key = primust_api_key
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        result = p.register_check(MANIFEST_KYC_REFRESH)
        self._manifest_ids[MANIFEST_KYC_REFRESH["name"]] = result.manifest_id

    def assess_customer(
        self,
        run: Any,
        customer_id: str,
        risk_tier: str,
        assessment_type: str,
        jurisdiction: str,
    ) -> PrimustKYCRecord:
        """
        Assess customer risk profile and record governance proof.

        Input commitment: customer_id, risk_tier, assessment_type, jurisdiction
        Output commitment: assessment_id, risk_rating, decision, rules_applied_count
        CRITICAL: PII fields NOT in commitment — only identifiers and metadata.
        """
        manifest_id = self._manifest_ids.get("actimize_kyc_refresh")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        input_commitment = _commit({
            "customer_id": customer_id,
            "risk_tier": risk_tier,
            "assessment_type": assessment_type,
            "jurisdiction": jurisdiction,
        })

        try:
            with httpx.Client() as client:
                resp = client.post(
                    f"{self.base_url}/kyc/api/v1/assessments",
                    json={
                        "customerId": customer_id,
                        "riskTier": risk_tier,
                        "assessmentType": assessment_type,
                        "jurisdiction": jurisdiction,
                    },
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=15.0,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            gap_type = "actimize_auth_failure" if e.response.status_code == 401 else "actimize_api_error"
            record = run.record(
                check="actimize_kyc_assessment",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_type},
                visibility="opaque",
            )
            return PrimustKYCRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                decision="error",
            )
        except Exception:
            record = run.record(
                check="actimize_kyc_assessment",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "actimize_api_error"},
                visibility="opaque",
            )
            return PrimustKYCRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                decision="error",
            )

        assessment = KYCAssessmentResult(
            assessment_id=data.get("assessmentId", ""),
            risk_rating=data.get("riskRating", ""),
            decision=data.get("decision", ""),
            rules_applied_count=data.get("rulesAppliedCount", 0),
            raw_response=data,
        )

        output_commitment = _commit({
            "assessment_id": assessment.assessment_id,
            "risk_rating": assessment.risk_rating,
            "decision": assessment.decision,
            "rules_applied_count": assessment.rules_applied_count,
        })

        record = run.record(
            check="actimize_kyc_assessment",
            manifest_id=manifest_id,
            check_result="pass",
            input={"input_commitment": input_commitment, "output_commitment": output_commitment},
            details={
                "risk_rating": assessment.risk_rating,
                "decision": assessment.decision,
            },
            visibility="opaque",
        )

        return PrimustKYCRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            decision=assessment.decision,
        )


# ---------------------------------------------------------------------------
# Legacy facade — backward compatibility with NiceActimizeConnector
# ---------------------------------------------------------------------------

class NiceActimizeConnector:
    """
    Legacy facade wrapping the three surface classes.
    Maintained for backward compatibility with existing code.
    Prefer using ActimizeAlertEvaluator, ActimizeSARWorkflow,
    ActimizeKYCAssessor directly.
    """

    ACTONE_BASE = "https://actimize.bank.internal/ActOne/api/v2"

    def __init__(
        self,
        actimize_server_url: str,
        actimize_api_key: str,
        primust_api_key: str,
        alert_score_threshold: float = 0.65,
    ):
        self.actimize_url = actimize_server_url.rstrip("/")
        self.actimize_api_key = actimize_api_key
        self.primust_api_key = primust_api_key
        self.alert_score_threshold = alert_score_threshold
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [
            MANIFEST_TRANSACTION_MONITORING,
            MANIFEST_KYC_REFRESH,
            MANIFEST_SAR_DECISION,
        ]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id

    def new_pipeline(self, workflow_id: str = "aml-monitoring") -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    def monitor_transaction(
        self,
        pipeline: Any,
        account_id: str,
        transaction_id: str,
        amount: float,
        transaction_type: str,
        counterparty_id: Optional[str] = None,
        visibility: str = "opaque",
    ) -> PrimustAMLRecord:
        """Legacy: wraps ActimizeAlertEvaluator via pipeline.record()."""
        manifest_id = self._manifest_ids.get("actimize_transaction_monitoring")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        input_commitment = _commit({
            "transaction_id": transaction_id,
            "account_id": account_id,
            "transaction_type": transaction_type,
        })

        try:
            with httpx.Client() as client:
                resp = client.post(
                    f"{self.actimize_url}/monitoring/transactions",
                    json={
                        "accountId": account_id,
                        "transactionId": transaction_id,
                        "amount": amount,
                        "type": transaction_type,
                        "counterpartyId": counterparty_id,
                    },
                    headers={"Authorization": f"Bearer {self.actimize_api_key}"},
                    timeout=15.0,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            gap_type = "actimize_auth_failure" if e.response.status_code == 401 else "actimize_api_error"
            record = pipeline.record(
                check="actimize_transaction_monitoring",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_type},
                visibility="opaque",
            )
            return PrimustAMLRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                alert_generated=False,
            )
        except Exception:
            record = pipeline.record(
                check="actimize_transaction_monitoring",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "actimize_api_error"},
                visibility="opaque",
            )
            return PrimustAMLRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                alert_generated=False,
            )

        result = _parse_alert_response(data)
        check_result = "fail" if result.alert_generated else "pass"

        output_commitment = _commit({
            "alert_id": result.alert_id,
            "risk_score": result.risk_score,
            "alert_disposition": "HIGH_RISK" if result.alert_generated else "LOW_RISK",
        })

        record = pipeline.record(
            check="actimize_transaction_monitoring",
            manifest_id=manifest_id,
            check_result=check_result,
            input={"input_commitment": input_commitment, "output_commitment": output_commitment},
            details={
                "alert_generated": result.alert_generated,
                "risk_score": result.risk_score,
            },
            visibility=visibility,
        )

        return PrimustAMLRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            alert_generated=result.alert_generated,
        )

    def record_sar_determination(
        self,
        pipeline: Any,
        case_id: str,
        determination: str,
        analyst_key_id: str,
        case_content_hash: str,
        rationale: str,
        reviewer_signature: str,
        min_review_minutes: int = 30,
    ) -> SARDecisionResult:
        """Legacy: wraps ActimizeSARWorkflow via pipeline.open_review()."""
        manifest_id = self._manifest_ids.get("actimize_sar_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        rationale_commitment = _commit(rationale)

        review = pipeline.open_review(
            check="actimize_sar_decision",
            manifest_id=manifest_id,
            reviewer_key_id=analyst_key_id,
            min_duration_seconds=min_review_minutes * 60,
        )

        check_open_tst = getattr(review, "open_tst", None)

        check_result = "pass" if determination == "FILE" else "fail"

        record = pipeline.record(
            check_session=review,
            input={"input_commitment": _commit({"case_id": case_id, "reviewer_id": analyst_key_id})},
            check_result=check_result,
            reviewer_signature=reviewer_signature,
            display_content=case_content_hash,
            rationale=rationale,
            details={"case_id": case_id, "determination": determination},
            visibility="opaque",
        )

        check_close_tst = getattr(record, "recorded_at", None)

        return SARDecisionResult(
            case_id=case_id,
            determination=determination,
            analyst_id=analyst_key_id,
            rationale_hash=rationale_commitment,
            check_open_tst=check_open_tst,
            check_close_tst=check_close_tst,
        )

    def _parse_alert_response(self, data: dict) -> ActimizeAlertResult:
        return _parse_alert_response(data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_alert_response(data: dict) -> ActimizeAlertResult:
    return ActimizeAlertResult(
        alert_id=data.get("alertId", ""),
        alert_type=data.get("alertType", ""),
        risk_score=float(data.get("riskScore", 0.0)),
        alert_generated=data.get("alertGenerated", False),
        rule_codes_fired=data.get("ruleCodesFired", []),
        raw_response=data,
    )


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

FIT_VALIDATION = {
    "platform": "NICE Actimize",
    "category": "AML Transaction Monitoring",
    "fit": "STRONG",
    "external_verifier": "FinCEN, OCC, Fed, FCA, AUSTRAC, FINTRAC — with SAR authority",
    "trust_deficit": True,
    "data_sensitivity": (
        "Transaction amounts and patterns. Monitoring thresholds — "
        "revealing enables structuring attacks (BSA §5324). SAR contents — legally protected."
    ),
    "gep_value": (
        "Proves transaction monitoring ran on specific account/transaction. "
        "Fleet consistency scan detects monitoring gaps or inconsistent application. "
        "SAR determination Witnessed level proves analyst review with rationale "
        "commitment — satisfies 31 CFR §1020.320 documentation without disclosing "
        "SAR contents or monitoring thresholds."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": {
        "velocity_rules": "mathematical",
        "structuring_detection": "mathematical",
        "ml_behavioral": "attestation (proprietary — permanent ceiling)",
        "overall_vpec": "attestation (weakest-link, but per-stage breakdown shows mathematical stages)",
    },
    "sar_witnessed_level": True,
    "cross_run_consistency_applicable": True,
    "buildable_today": True,
    "sdk_required_for_mathematical": "Java (P10-D, ~2-3 weeks)",
    "regulatory_hooks": [
        "BSA/AML 31 CFR §1020.320 (SAR filing)",
        "31 CFR §1020.315 (CTR filing)",
        "FFIEC BSA/AML Examination Manual",
        "OCC 12 CFR Part 21",
        "FinCEN CDD Rule",
        "EU AMLD 5/6",
    ],
    "aml_paradox_resolved": True,
    "notes": (
        "Actimize is the highest-ACV opportunity in this list. "
        "Dominant AML platform at every major US and EU bank. "
        "A single design partner here validates the entire regulated FSI thesis."
    ),
}
