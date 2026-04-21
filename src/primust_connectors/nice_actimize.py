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

Key distinction from ComplyAdvantage:
  ComplyAdvantage = entity screening (who is this person?)
  Actimize = transaction behavior monitoring (what is this person doing?)
  Both hit the AML paradox. Different verifier concern:
    - ComplyAdvantage: is this entity on a watchlist?
    - Actimize: is this transaction pattern suspicious per our monitoring rules?
  Revealing Actimize velocity thresholds enables structuring attacks (BSA §5324).
  GEP proves monitoring ran without revealing the thresholds.

NICE Actimize REST API: Actimize Risk Case Manager API + ActOne REST API
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx
import primust


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
            # Attestation today (REST). Mathematical post-Java SDK in-process.
            # Velocity = count(transactions, 24h window) >= threshold
            # This IS an arithmetic constraint — expressible as Noir circuit.
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Transaction count within rolling time window vs configured threshold",
            # NOTE: threshold value NOT included in manifest — revealing enables structuring
            # This is the correct visibility choice even at Mathematical level:
            # the manifest proves a threshold check ran; threshold value = opaque config
        },
        {
            "stage": 2,
            "name": "amount_threshold",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Transaction amount vs regulatory reporting threshold ($10,000 CTR)",
            # CTR threshold ($10k) IS public — could be transparent
            # SAR thresholds are NOT public — must be opaque
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
        },
        {
            "stage": 4,
            "name": "behavioral_ml_model",
            "type": "ml_model",
            "proof_level": "attestation",  # Actimize ML is proprietary, always attestation
            "purpose": "Behavioral anomaly score — deviation from account baseline",
        },
        {
            "stage": 5,
            "name": "composite_risk_score",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Weighted composite risk score >= alert generation threshold",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 1,  # transaction monitoring — near-realtime
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
        },
        {
            "stage": 2,
            "name": "edd_trigger_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Customer risk factors present in EDD trigger criteria",
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
        "Analyst review + determination to file or no-file."
        "Uses Witnessed level — human analyst decision with VDF time proof."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "alert_review",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "purpose": "Alert reviewed against case evidence",
        },
        {
            "stage": 2,
            "name": "analyst_determination",
            # This is a Witnessed level stage — human made a decision
            # rationale_hash required by BSA/AML compliance programs
            "type": "custom_code",
            "proof_level": "witnessed",
            "purpose": "BSA officer determination: file SAR or close alert with documented rationale",
            "reference": "BSA/AML Compliance Program — 31 CFR §1020.320",
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
    alert_type: str  # "VELOCITY" | "STRUCTURING" | "BEHAVIORAL" | "COMPOSITE"
    risk_score: float
    alert_generated: bool
    rule_codes_fired: list[str]
    raw_response: dict


@dataclass
class SARDecisionResult:
    case_id: str
    determination: str  # "FILE" | "NO_FILE" | "PENDING"
    analyst_id: str
    rationale_hash: Optional[str]  # set when using open_review()


@dataclass
class PrimustAMLRecord:
    commitment_hash: str
    record_id: str
    proof_level: str
    alert_generated: bool
    vpec_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class NiceActimizeConnector:
    """
    Wraps NICE Actimize transaction monitoring and SAR decision workflow.

    The AML paradox in concrete terms:
        A FinCEN examiner reviewing BSA program compliance asks:
        "Prove your transaction monitoring ran on account X during Q3."
        Current answer: "Here are our logs." (requires trust + data disclosure)
        With Primust: VPEC proves monitoring ran, input commitment proves
        it was account X's transactions, threshold stages prove rules applied —
        without disclosing the threshold values that would enable structuring.

    SAR workflow:
        When Actimize generates an alert, a BSA officer makes a determination.
        That determination is a human decision that should be Witnessed level.
        p.open_review() + p.record(reviewer_signature=..., rationale=...) gives
        cryptographic proof the analyst reviewed specific content, spent minimum
        time, and stated a rationale — satisfying 31 CFR §1020.320 documentation
        requirements without disclosing the SAR contents.
    """

    ACTONE_BASE = "https://actimize.bank.internal/ActOne/api/v2"  # typical on-prem URL pattern

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

    # ------------------------------------------------------------------
    # Transaction monitoring
    # ------------------------------------------------------------------

    def monitor_transaction(
        self,
        pipeline: primust.Pipeline,
        account_id: str,
        transaction_id: str,
        amount: float,
        transaction_type: str,
        counterparty_id: Optional[str] = None,
        visibility: str = "opaque",  # transaction details are customer financial data
    ) -> PrimustAMLRecord:
        """
        Submit transaction to Actimize monitoring and record VPEC.

        Visibility "opaque" by default:
          - Proves monitoring ran on this account/transaction
          - Does NOT reveal amount, counterparty, or which rules fired
          - Regulator can request NDA audit path for detailed evidence
          - Structuring thresholds remain protected
        """
        manifest_id = self._manifest_ids.get("actimize_transaction_monitoring")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Call Actimize monitoring API
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

        result = self._parse_alert_response(data)
        check_result = "fail" if result.alert_generated else "pass"

        # Input commitment: account_id + transaction_id + amount
        # Amount committed — proves the monitoring ran on the actual amount
        # without revealing it to the verifier (opaque visibility)
        record = pipeline.record(
            check="actimize_transaction_monitoring",
            manifest_id=manifest_id,
            input=f"{account_id}|{transaction_id}|{amount}|{transaction_type}",
            check_result=check_result,
            details={
                "alert_generated": result.alert_generated,
                "risk_score": result.risk_score,
                # rule_codes_fired NOT included — reveals monitoring methodology
            },
            visibility=visibility,
        )

        return PrimustAMLRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            alert_generated=result.alert_generated,
        )

    # ------------------------------------------------------------------
    # SAR determination — Witnessed level
    # ------------------------------------------------------------------

    def record_sar_determination(
        self,
        pipeline: primust.Pipeline,
        case_id: str,
        determination: str,  # "FILE" | "NO_FILE"
        analyst_key_id: str,  # registered reviewer key
        case_content_hash: str,  # hash of what analyst reviewed
        rationale: str,  # analyst's documented rationale
        reviewer_signature: str,  # Ed25519 signature from analyst's key
        min_review_minutes: int = 30,  # BSA programs typically require documented review time
    ) -> SARDecisionResult:
        """
        Record a SAR filing determination with Witnessed level proof.

        31 CFR §1020.320 requires BSA officers to document:
          - What was reviewed
          - The determination made
          - The rationale
        This produces cryptographic proof of all three:
          - display_hash proves analyst saw the actual case content
          - rationale_hash commits the documented rationale
          - VDF timestamps prove minimum review time elapsed
          - Ed25519 signature proves this specific analyst signed it
        All offline-verifiable. Primust never holds analyst credentials.
        """
        manifest_id = self._manifest_ids.get("actimize_sar_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Open a Witnessed review session
        review = pipeline.open_review(
            check="actimize_sar_decision",
            manifest_id=manifest_id,
            reviewer_key_id=analyst_key_id,
            min_duration_seconds=min_review_minutes * 60,
        )
        # review.open_tst = RFC 3161 timestamp (review start)

        check_result = "pass" if determination == "FILE" else "fail"

        # Record with full Witnessed payload
        pipeline.record(
            check_session=review,
            input=f"case:{case_id}",
            check_result=check_result,
            reviewer_signature=reviewer_signature,
            display_content=case_content_hash,  # committed locally — proves what analyst saw
            rationale=rationale,  # committed locally → rationale_hash
            details={"case_id": case_id, "determination": determination},
            visibility="opaque",  # SAR contents are legally protected
        )

        return SARDecisionResult(
            case_id=case_id,
            determination=determination,
            analyst_id=analyst_key_id,
            rationale_hash=None,  # populated in VPEC by SDK
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_alert_response(self, data: dict) -> ActimizeAlertResult:
        return ActimizeAlertResult(
            alert_id=data.get("alertId", ""),
            alert_type=data.get("alertType", ""),
            risk_score=float(data.get("riskScore", 0.0)),
            alert_generated=data.get("alertGenerated", False),
            rule_codes_fired=data.get("ruleCodesFired", []),
            raw_response=data,
        )


ACTIMIZE_JAVA_UPGRADE_NOTE = """
When Java SDK (P10-D) ships, deterministic stages hit Mathematical ceiling:

  // In-process — direct Actimize Java API
  import com.actimize.sam.RuleEngine;
  import com.primust.Primust;

  RuleEngine engine = RuleEngine.getInstance(config);
  TransactionData tx = TransactionData.from(transactionPayload);
  engine.evaluate(tx);

  // Velocity rule: count(tx in 24h window) >= threshold
  // This is arithmetic — expressible as Noir circuit
  // manifest declares: method=threshold_comparison, stage_type=deterministic_rule
  // Proof level: MATHEMATICAL

  p.record(
    RecordInput.builder()
      .check("actimize_velocity_rule")
      .manifestId(manifestId)
      .input(tx.toBytes())
      .checkResult(tx.getVelocityResult())
      .build()
  );

  // The structuring detection (multiple sub-threshold txs summing to reportable)
  // is also arithmetic — Mathematical proof that the sum was computed correctly
  // without revealing individual transaction amounts.

  // ML behavioral model remains Attestation — proprietary Actimize model.
  // Per-stage breakdown in VPEC: velocity=mathematical, ml=attestation.
  // Overall VPEC: attestation (weakest-link), but examiner sees the breakdown.
"""


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
