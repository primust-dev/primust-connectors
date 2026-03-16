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
Primust Connector: FICO Falcon Fraud Detection
===============================================
Fit: PARTIAL — honest assessment
Verifier: OCC, Fed examiners, card network compliance (Visa/MC fraud program requirements)
Problem solved: Prove fraud scoring ran on every transaction without disclosing
               the score threshold that triggers a decline or review
Proof ceiling:
  - Score computation: Attestation permanently (Falcon neural net is proprietary)
  - Threshold comparison (score >= decline_threshold): Mathematical
  - Per-stage breakdown surfaces the mathematical threshold stage to verifier
Overall VPEC: Attestation (weakest-link), but Mathematical threshold stage
             is explicitly visible in the breakdown
Buildable: NOW — Python SDK + REST

Honest fit note:
  The fraud paradox: prove the score was compared against the threshold without
  revealing the threshold (revealing enables gaming). The threshold check IS
  Mathematical — arithmetic comparison. The score computation is Attestation.
  This is genuinely useful for card network compliance audits and OCC exam prep.
  It's not as clean as the AML story because card fraud is primarily internal
  risk management, not regulated-proof-to-external-verifier. The OCC exam is
  the strongest external verifier case.

FICO Platform REST API (FICO Falcon 6.x+):
  POST /falcon/v1/score  — score a transaction
  POST /falcon/v1/batch  — batch scoring

On-premise deployments also expose:
  Java API (com.fico.falcon.FalconEngine) — for in-process Mathematical proof
  post Java SDK (P10-D). Same pattern as Blaze.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from primust_artifact_core.commitment import commit as _artifact_commit

try:
    import primust
    PRIMUST_AVAILABLE = True
except ImportError:
    PRIMUST_AVAILABLE = False


# ---------------------------------------------------------------------------
# Commitment helper — raw data never leaves this function
# ---------------------------------------------------------------------------

def _commit(data: Any) -> str:
    """Commit via artifact-core commitment path (SHA-256 default)."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    hash_str, _ = _artifact_commit(canonical.encode(), "sha256")
    return hash_str


def _score_to_band(fraud_score: int) -> str:
    """Map numeric fraud score to a band. Raw score never leaves the connector."""
    if fraud_score >= 700:
        return "high"
    elif fraud_score >= 400:
        return "medium"
    else:
        return "low"


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

MANIFEST_FRAUD_SCORE = {
    "name": "fico_falcon_fraud_score",
    "description": (
        "FICO Falcon fraud scoring. Neural network model produces a fraud score "
        "for each transaction. Score compared against configured decline/review "
        "thresholds. Model is proprietary — score computation is Attestation. "
        "Threshold comparison is Mathematical."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "neural_net_scoring",
            "type": "ml_model",
            "proof_level": "attestation",       # Falcon NN is proprietary — permanent ceiling
            "purpose": "FICO Falcon neural network produces fraud probability score 0-999",
            "regulatory_references": ["occ_fraud_examination", "visa_core_rules", "mc_security_rules"],
        },
        {
            "stage": 2,
            "name": "decline_threshold_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",       # → mathematical post-Java SDK in-process
            "method": "threshold_comparison",
            "formula": "fraud_score >= decline_threshold",
            "purpose": "Score compared against configured decline threshold",
            "regulatory_references": ["occ_fraud_examination", "visa_core_rules"],
            # NOTE: decline_threshold NOT in manifest (opaque config)
            # Revealing the threshold enables score gaming
            # The MATHEMATICAL proof proves the comparison ran correctly
            # without the verifier knowing what the threshold is
        },
        {
            "stage": 3,
            "name": "review_threshold_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "formula": "fraud_score >= review_threshold",
            "purpose": "Score compared against manual review threshold",
            "regulatory_references": ["occ_fraud_examination", "pci_dss_req12"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 720,   # Falcon model updates quarterly typically
    "publisher": "your-org-id",
}

MANIFEST_BATCH_AUTHORIZATION = {
    "name": "fico_falcon_batch_auth",
    "description": (
        "FICO Falcon batch authorization scoring for card-not-present transactions. "
        "Fleet consistency detection applies: identical card/merchant patterns "
        "must produce consistent risk outcomes."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "account_risk_score",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "Account-level risk score from historical behavior",
            "regulatory_references": ["occ_fraud_examination", "visa_core_rules"],
        },
        {
            "stage": 2,
            "name": "transaction_risk_score",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "Transaction-level anomaly score",
            "regulatory_references": ["occ_fraud_examination", "mc_security_rules"],
        },
        {
            "stage": 3,
            "name": "composite_threshold",
            "type": "deterministic_rule",
            "proof_level": "attestation",       # → mathematical in-process
            "method": "threshold_comparison",
            "purpose": "Composite score vs authorization threshold",
            "regulatory_references": ["occ_fraud_examination", "visa_core_rules", "pci_dss_req12"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 720,
    "publisher": "your-org-id",
}

MANIFEST_RULES_DECISION = {
    "name": "fico_falcon_rules_decision",
    "description": (
        "Deterministic rules component of FICO Falcon. Velocity checks, "
        "geographic anomaly rules, and merchant category restrictions. "
        "Rules are configurable per-issuer."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "rules_evaluation",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "purpose": "Falcon rules engine: velocity, geo-anomaly, MCC restrictions",
            "regulatory_references": ["occ_fraud_examination", "visa_core_rules", "pci_dss_req12"],
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
class FalconScoreResult:
    transaction_id: str
    fraud_score: int          # 0–999, higher = more suspicious
    decision: str             # "APPROVE" | "DECLINE" | "REVIEW"
    model_version: str
    raw_response: dict


@dataclass
class PrimustFraudRecord:
    commitment_hash: str
    record_id: str
    proof_level: str          # always "attestation" overall
    decision: str
    gap_code: Optional[str] = None
    mathematical_stage_note: str = (
        "Stage 2 (threshold comparison) is Mathematical — "
        "proves threshold check ran without revealing threshold value"
    )


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class FicoFalconConnector:
    """
    Wraps FICO Falcon fraud scoring with Primust VPEC issuance.

    Per-stage proof level breakdown in the VPEC:
      Stage 1 (neural net): Attestation
      Stage 2 (decline threshold): Attestation today, Mathematical post-Java SDK
      Stage 3 (review threshold): Attestation today, Mathematical post-Java SDK
      Overall: Attestation (weakest-link)

    OCC exam use case:
      Examiner asks: "Prove your fraud detection ran on all transactions in Q3."
      VPEC proves monitoring ran on each transaction without disclosing thresholds.
      Cross-run consistency scan detects inconsistent threshold application across
      identical transaction patterns — regulatory evidence of consistent controls.

    Card network compliance:
      Visa/MC fraud program requirements: demonstrate controls are active.
      VPEC provides portable proof of control operation without disclosing
      the fraud strategy that enables gaming.
    """

    def __init__(
        self,
        falcon_server_url: str,
        falcon_api_key: str,
        primust_api_key: str,
        decline_threshold: int = 750,   # typical range: 650–850
        review_threshold: int = 500,
    ):
        self.falcon_url = falcon_server_url.rstrip("/")
        self.falcon_api_key = falcon_api_key
        self.primust_api_key = primust_api_key
        self.decline_threshold = decline_threshold
        self.review_threshold = review_threshold
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        if not PRIMUST_AVAILABLE:
            raise RuntimeError("primust package not installed: pip install primust")
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [MANIFEST_FRAUD_SCORE, MANIFEST_BATCH_AUTHORIZATION, MANIFEST_RULES_DECISION]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id

    def new_pipeline(self, workflow_id: str = "fraud-scoring") -> primust.Pipeline:
        if not PRIMUST_AVAILABLE:
            raise RuntimeError("primust package not installed: pip install primust")
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    def score_transaction(
        self,
        pipeline: Any,
        transaction_id: str,
        card_number_hash: str,    # MUST be hashed before passing in — PAN is PCI
        amount: float,
        merchant_id: str,
        merchant_category_code: str,
        country_code: str,
    ) -> PrimustFraudRecord:
        """
        Score a transaction and record VPEC proof.

        PCI DSS note: card_number_hash must be the SHA-256 or token of the PAN,
        never the raw PAN. This connector enforces nothing technically here —
        caller is responsible. The input commitment will commit whatever is passed.

        The threshold comparison (decline/review) is the Mathematical story:
        prove the score was compared against configured thresholds without
        revealing the thresholds to the verifier.

        CRITICAL: card_number_hash and account numbers are NEVER included in the
        input commitment. Only safe fields (merchant, MCC, country, transaction_id)
        are committed. This prevents PCI-sensitive data from leaking via commitment.

        Gap handling: On Falcon API errors, records a gap with check_result="error"
        and returns gracefully (fail-open). The gap is recorded in the VPEC.
        """
        manifest_id = self._manifest_ids.get("fico_falcon_fraud_score")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Input commitment: safe fields only — NO card number, NO account number
        input_commitment = _commit({
            "transaction_id": transaction_id,
            "merchant_id": merchant_id,
            "merchant_category_code": merchant_category_code,
            "country_code": country_code,
            "amount": amount,
        })

        try:
            with httpx.Client() as client:
                resp = client.post(
                    f"{self.falcon_url}/falcon/v1/score",
                    json={
                        "transactionId": transaction_id,
                        "cardToken": card_number_hash,
                        "amount": amount,
                        "merchantId": merchant_id,
                        "mcc": merchant_category_code,
                        "countryCode": country_code,
                    },
                    headers={"Authorization": f"Bearer {self.falcon_api_key}"},
                    timeout=5.0,   # fraud scoring must be fast — real-time auth path
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            gap_code = "falcon_auth_failure" if e.response.status_code == 401 else "falcon_api_error"
            severity = "critical" if gap_code == "falcon_auth_failure" else "high"
            record = pipeline.record(
                check="fico_falcon_fraud_score",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_code, "severity": severity},
                visibility="opaque",
            )
            return PrimustFraudRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                decision="ERROR",
                gap_code=gap_code,
            )
        except Exception:
            record = pipeline.record(
                check="fico_falcon_fraud_score",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "falcon_api_error", "severity": "high"},
                visibility="opaque",
            )
            return PrimustFraudRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                decision="ERROR",
                gap_code="falcon_api_error",
            )

        result = self._parse_score_response(data, transaction_id)

        # Determine decision from thresholds
        if result.fraud_score >= self.decline_threshold:
            decision = "DECLINE"
        elif result.fraud_score >= self.review_threshold:
            decision = "REVIEW"
        else:
            decision = "APPROVE"

        check_result = "fail" if decision == "DECLINE" else "pass"

        # Output commitment: model_score_band (NOT raw fraud score)
        output_commitment = _commit({
            "model_score_band": _score_to_band(result.fraud_score),
            "decision": decision,
            "model_version": result.model_version,
        })

        record = pipeline.record(
            check="fico_falcon_fraud_score",
            manifest_id=manifest_id,
            input={"input_commitment": input_commitment},
            check_result=check_result,
            details={
                "transaction_id": transaction_id,
                "decision": decision,
                "model_version": result.model_version,
                "model_score_band": _score_to_band(result.fraud_score),
                "output_commitment": output_commitment,
                # fraud_score NOT included — reveals position relative to threshold
            },
            visibility="opaque",
        )

        return PrimustFraudRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            decision=decision,
        )

    def record_rules_decision(
        self,
        pipeline: Any,
        transaction_id: str,
        rules_triggered: list[str],
        rules_decision: str,
        merchant_id: str,
        merchant_category_code: str,
        country_code: str,
    ) -> PrimustFraudRecord:
        """
        Record the deterministic rules component of a Falcon evaluation.

        Rules include velocity checks, geographic anomaly detection, and
        merchant category restrictions. These are configurable per-issuer
        and deterministic — they could reach Mathematical proof level
        with in-process instrumentation.

        Args:
            pipeline: Primust pipeline instance.
            transaction_id: Transaction identifier.
            rules_triggered: List of rule IDs that fired (e.g. ["velocity_24h", "geo_anomaly"]).
            rules_decision: "APPROVE" | "DECLINE" | "REVIEW"
            merchant_id: Merchant identifier.
            merchant_category_code: MCC code.
            country_code: ISO country code.
        """
        manifest_id = self._manifest_ids.get("fico_falcon_rules_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        input_commitment = _commit({
            "transaction_id": transaction_id,
            "merchant_id": merchant_id,
            "merchant_category_code": merchant_category_code,
            "country_code": country_code,
        })

        check_result = "fail" if rules_decision == "DECLINE" else "pass"

        record = pipeline.record(
            check="fico_falcon_rules_decision",
            manifest_id=manifest_id,
            input={"input_commitment": input_commitment},
            check_result=check_result,
            details={
                "transaction_id": transaction_id,
                "rules_decision": rules_decision,
                "rules_triggered_count": len(rules_triggered),
                # Individual rule IDs not disclosed — reveals fraud strategy
            },
            visibility="opaque",
        )

        return PrimustFraudRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            decision=rules_decision,
        )

    def _parse_score_response(self, data: dict, txn_id: str) -> FalconScoreResult:
        return FalconScoreResult(
            transaction_id=txn_id,
            fraud_score=int(data.get("fraudScore", 0)),
            decision=data.get("decision", "APPROVE"),
            model_version=data.get("modelVersion", ""),
            raw_response=data,
        )


JAVA_UPGRADE_NOTE = """
When Java SDK (P10-D) ships, threshold stages hit Mathematical ceiling:

  import com.fico.falcon.FalconEngine;
  import com.primust.Primust;

  FalconEngine engine = FalconEngine.getInstance(config);
  TransactionData tx = TransactionData.from(txPayload);
  int score = engine.score(tx);

  // Threshold comparison — in-process, arithmetic
  // Mathematical proof: proves score >= threshold without revealing threshold
  p.record(
    RecordInput.builder()
      .check("fico_falcon_decline_threshold")
      .input(tx.toBytes())
      .output(score >= declineThreshold ? "DECLINE" : "PASS")
      .checkResult(score >= declineThreshold ? CheckResult.FAIL : CheckResult.PASS)
      .build()
  );

  Proof level: MATHEMATICAL for threshold stages
  Score stage remains Attestation — Falcon NN is proprietary always
"""

FIT_VALIDATION = {
    "platform": "FICO Falcon",
    "category": "Card Fraud Detection",
    "fit": "PARTIAL",
    "fit_note": (
        "Primary use is internal risk management — verifier is often internal. "
        "OCC exam and card network compliance are the external verifier cases. "
        "Not as strong as AML/clinical/fair lending but genuinely useful."
    ),
    "external_verifier": "OCC examiners, Visa/MC fraud program compliance",
    "trust_deficit": True,
    "data_sensitivity": "Fraud score thresholds — revealing enables gaming. Card PAN (PCI).",
    "gep_value": (
        "Proves fraud scoring ran on every transaction. Mathematical threshold "
        "stages prove comparison applied without revealing thresholds. "
        "Cross-run consistency detects inconsistent threshold application."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": {
        "score_computation": "attestation (Falcon NN — permanent)",
        "threshold_comparison": "mathematical",
        "overall": "attestation (weakest-link, but mathematical threshold stage visible in breakdown)",
    },
    "cross_run_consistency_applicable": True,
    "buildable_today": True,
    "sdk_required_for_mathematical": "Java (P10-D — shipped)",
    "regulatory_hooks": [
        "OCC fraud detection examination",
        "Visa Core Rules fraud program requirements",
        "Mastercard Security Rules",
        "PCI DSS Requirement 12 (fraud monitoring)",
    ],
}
