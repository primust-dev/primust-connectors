"""
Primust Connector: Pega Customer Decision Hub (CDH) / Next-Best-Action
=======================================================================
Fit: WEAK-to-MODERATE — honest assessment required
Verifier: Depends entirely on deployment context
Problem: Pega CDH is opaque by design — proprietary decisioning, REST-only
         external surface, no in-process hook even with Java access
Proof ceiling: Attestation PERMANENTLY — internal engine is opaque regardless
               of SDK language. Java SDK does NOT change this ceiling.
               This is the key difference from Blaze/ODM.
Buildable: NOW — Python SDK + REST

Honest fit assessment:
  Most Pega deployments are internal decisioning — marketing offers,
  service routing, sales recommendations. No external verifier problem.
  The legitimate GEP use cases for Pega:
    1. Regulated NBA in financial services: Pega used for credit limit
       increase decisions or hardship forbearance routing. OCC/CFPB
       could be the external verifier. This is real.
    2. Insurance: Pega routing claims to SIU or adjusters. State DOI
       could ask for proof of consistent routing.
    3. GDPR Article 22: Automated decision-making disclosure. Prove
       the decision was made by algorithm X, not human override.
       Pega produces the GDPR audit trail — VPEC makes it portable.
  If none of these apply, this is just an expensive log with commitment.
  Don't sell it as more than it is.

Pega DX API (REST):
  POST /prweb/api/application/v2/cases     — create case
  POST /prweb/api/application/v2/actions   — execute action
  GET  /prweb/api/application/v2/cases/{id} — get decision outcome

Pega NBA Decision API:
  POST /prweb/api/v1/channels/web/actions  — get NBA outcome for customer
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx
import primust


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

MANIFEST_NBA_DECISION = {
    "name": "pega_nba_decision",
    "description": (
        "Pega Customer Decision Hub Next-Best-Action. "
        "Proprietary Pega AI/rules engine evaluates customer context "
        "and produces ranked action recommendations. "
        "Engine internals permanently opaque — Attestation ceiling only."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "eligibility_evaluation",
            "type": "custom_code",
            "proof_level": "attestation",  # Pega engine — always attestation
            "purpose": "Pega eligibility rules evaluate customer against action criteria",
        },
        {
            "stage": 2,
            "name": "ai_ranking",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "Pega AI model ranks eligible actions by propensity",
        },
        {
            "stage": 3,
            "name": "arbitration",
            "type": "custom_code",
            "proof_level": "attestation",
            "purpose": "Business constraints applied via Pega arbitration (budget, limits, exclusions)",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 168,
    "publisher": "your-org-id",
}

MANIFEST_CREDIT_ACTION = {
    "name": "pega_credit_limit_decision",
    "description": (
        "Pega CDH credit limit increase / hardship forbearance routing decision. "
        "Regulated NBA — OCC/CFPB external verifier context. "
        "Attestation ceiling — Pega engine internals opaque. "
        "GDPR Art. 22 automated decision disclosure use case."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "bureau_data_evaluation",
            "type": "custom_code",
            "proof_level": "attestation",
            "purpose": "Bureau data pulled and evaluated by Pega rules",
        },
        {
            "stage": 2,
            "name": "policy_filter",
            "type": "custom_code",
            "proof_level": "attestation",
            "purpose": "Credit policy rules applied (exclusions, caps, product eligibility)",
        },
        {
            "stage": 3,
            "name": "decision_output",
            "type": "custom_code",
            "proof_level": "attestation",
            "purpose": "Final credit decision output with reason codes",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 168,
    "publisher": "your-org-id",
}

MANIFEST_GDPR_AUTOMATED_DECISION = {
    "name": "pega_gdpr_automated_decision",
    "description": (
        "GDPR Article 22 automated decision record. "
        "Proves an automated decision was made by the Pega system "
        "(not human override) with the stated input context. "
        "Portable proof for GDPR data subject access requests."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "automated_decision",
            "type": "custom_code",
            "proof_level": "attestation",
            "purpose": "Automated decision produced by Pega CDH without human override",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 8760,  # one year
    "publisher": "your-org-id",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PegaNBAResult:
    customer_id: str
    top_action: str
    action_group: str
    propensity: float
    treatment_id: str
    raw_response: dict


@dataclass
class PegaCreditDecisionResult:
    customer_id: str
    decision: str  # "INCREASE" | "MAINTAIN" | "DECREASE" | "DECLINE" | "ROUTE_TO_REVIEW"
    new_limit: Optional[float]
    reason_codes: list[str]
    raw_response: dict


@dataclass
class PrimustPegaRecord:
    commitment_hash: str
    record_id: str
    proof_level: str  # always "attestation"
    decision: str


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class PegaDecisioningConnector:
    """
    Wraps Pega Customer Decision Hub with Primust VPEC issuance.

    IMPORTANT: Proof ceiling is Attestation permanently. Pega engine is
    opaque by design. Java SDK does NOT change this — there is no in-process
    hook that exposes rule execution internals.

    Where this is legitimately useful:
      - Regulated financial services NBA (credit, forbearance) — OCC/CFPB verifier
      - Insurance claim routing — state DOI verifier
      - GDPR Article 22 — data subject can verify automated decision occurred
      - CCPA automated decision disclosure

    Where it adds no real value:
      - Internal marketing offers, sales routing — no external verifier
      - Any purely internal Pega workflow
    """

    def __init__(
        self,
        pega_server_url: str,
        pega_client_id: str,
        pega_client_secret: str,
        primust_api_key: str,
    ):
        self.pega_url = pega_server_url.rstrip("/")
        self.pega_client_id = pega_client_id
        self.pega_client_secret = pega_client_secret
        self.primust_api_key = primust_api_key
        self._manifest_ids: dict[str, str] = {}
        self._access_token: Optional[str] = None

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [
            MANIFEST_NBA_DECISION,
            MANIFEST_CREDIT_ACTION,
            MANIFEST_GDPR_AUTOMATED_DECISION,
        ]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id

    def new_pipeline(self, workflow_id: str = "pega-decisions") -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    # ------------------------------------------------------------------
    # Next-Best-Action decision
    # ------------------------------------------------------------------

    def get_nba_decision(
        self,
        pipeline: primust.Pipeline,
        customer_id: str,
        channel: str = "web",
        context: Optional[dict] = None,
        visibility: str = "opaque",
    ) -> PrimustPegaRecord:
        """Get NBA decision for a customer and record VPEC proof."""
        manifest_id = self._manifest_ids.get("pega_nba_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        token = self._get_token()
        with httpx.Client() as client:
            resp = client.post(
                f"{self.pega_url}/prweb/api/v1/channels/{channel}/actions",
                json={"customerID": customer_id, "context": context or {}},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()

        result = self._parse_nba_response(data, customer_id)

        record = pipeline.record(
            check="pega_nba_decision",
            manifest_id=manifest_id,
            input=f"{customer_id}|{channel}",
            check_result="pass",
            details={
                "customer_id": customer_id,
                "top_action": result.top_action,
                "action_group": result.action_group,
            },
            visibility=visibility,
        )

        return PrimustPegaRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            decision=result.top_action,
        )

    # ------------------------------------------------------------------
    # Regulated credit decision (OCC/CFPB context)
    # ------------------------------------------------------------------

    def execute_credit_decision(
        self,
        pipeline: primust.Pipeline,
        customer_id: str,
        decision_type: str,  # "CREDIT_LIMIT_REVIEW" | "HARDSHIP_FORBEARANCE"
        customer_context: dict,  # income, bureau score, delinquency — committed locally
        visibility: str = "opaque",
    ) -> PrimustPegaRecord:
        """
        Execute a regulated credit decision and record VPEC proof.

        customer_context is committed locally — never leaves your environment.
        The VPEC proves the decision ran on this customer's specific context
        without disclosing the context to the OCC examiner.
        GDPR Art. 22: input commitment proves the decision was automated,
        not a human override.
        """
        manifest_id = self._manifest_ids.get("pega_credit_limit_decision")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        token = self._get_token()
        with httpx.Client() as client:
            resp = client.post(
                f"{self.pega_url}/prweb/api/application/v2/cases",
                json={
                    "caseTypeID": f"BANK-CREDITOPS-WORK-{decision_type}",
                    "content": {"customerID": customer_id, **customer_context},
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()

        decision_result = self._parse_credit_response(data, customer_id)
        check_result = "pass" if decision_result.decision not in ("DECLINE",) else "fail"

        record = pipeline.record(
            check="pega_credit_limit_decision",
            manifest_id=manifest_id,
            input={
                **{"customer_id": customer_id, "decision_type": decision_type},
                **customer_context,
            },
            check_result=check_result,
            details={
                "customer_id": customer_id,
                "decision": decision_result.decision,
                "reason_code_count": len(decision_result.reason_codes),
                # reason codes NOT included — reveals decision criteria
            },
            visibility=visibility,
        )

        return PrimustPegaRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            decision=decision_result.decision,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        if self._access_token:
            return self._access_token
        with httpx.Client() as client:
            resp = client.post(
                f"{self.pega_url}/prweb/PRRestService/oauth2/v1/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.pega_client_id,
                    "client_secret": self.pega_client_secret,
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    def _parse_nba_response(self, data: dict, customer_id: str) -> PegaNBAResult:
        actions = data.get("actions", [{}])
        top = actions[0] if actions else {}
        return PegaNBAResult(
            customer_id=customer_id,
            top_action=top.get("actionName", ""),
            action_group=top.get("group", ""),
            propensity=float(top.get("propensity", 0.0)),
            treatment_id=top.get("treatmentID", ""),
            raw_response=data,
        )

    def _parse_credit_response(self, data: dict, customer_id: str) -> PegaCreditDecisionResult:
        content = data.get("content", {})
        return PegaCreditDecisionResult(
            customer_id=customer_id,
            decision=content.get("Decision", "MAINTAIN"),
            new_limit=content.get("NewCreditLimit"),
            reason_codes=content.get("ReasonCodes", []),
            raw_response=data,
        )


FIT_VALIDATION = {
    "platform": "Pega Customer Decision Hub",
    "category": "Next-Best-Action / Regulated Decisioning",
    "fit": "PARTIAL — context dependent",
    "fit_note": (
        "Only valuable for regulated NBA deployments with external verifier. "
        "Internal marketing/service workflows: no GEP value. "
        "Financial services credit decisions + GDPR Art. 22: real value."
    ),
    "external_verifier": "OCC, CFPB (credit decisions), state DOI (insurance), GDPR data subjects",
    "trust_deficit": True,
    "data_sensitivity": "Customer financial context, decision criteria (reveals underwriting strategy)",
    "gep_value": (
        "For regulated deployments: proves automated decision ran on specific customer context. "
        "GDPR Art. 22: proves decision was automated, not human override. "
        "OCC exam: proves consistent decisioning without disclosing strategy."
    ),
    "proof_ceiling": "attestation (permanent — Pega engine is opaque, Java SDK irrelevant)",
    "java_sdk_changes_ceiling": False,  # explicitly called out
    "cross_run_consistency_applicable": True,
    "buildable_today": True,
    "regulatory_hooks": [
        "ECOA (credit decisions)",
        "GDPR Article 22 (automated decision-making)",
        "CCPA automated decision disclosure",
        "OCC model risk management SR 11-7",
    ],
}
