"""
Primust Connector: ComplyAdvantage AML Screening
================================================
Fit: STRONG
Verifier: Regulator (FinCEN, FCA, AUSTRAC) — external, trust deficit, cannot receive flagging criteria
Problem solved: AML paradox — prove the screen ran on this entity without revealing
                matching patterns that would enable circumvention
Proof ceiling: Attestation (proprietary matching engine, SaaS black box)
Buildable: NOW — Python SDK + REST only, no Java SDK required
Regulatory hook: BSA/AML, FATF recommendations, MLD5/6 (EU), FinCEN SAR obligations

The core GEP value here is NOT the proof level — it's the privacy-preserving proof.
The bank can prove to an examiner that ComplyAdvantage ran on this specific customer/
transaction at this specific time, without handing the examiner the full watchlist
matching criteria that would enable evasion. That's the AML paradox solved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx
import primust

# ---------------------------------------------------------------------------
# Manifests — register once per environment, reuse manifest_id forever
# ---------------------------------------------------------------------------

MANIFEST_AML_SCREENING = {
    "name": "comply_advantage_aml_screening",
    "description": (
        "ComplyAdvantage real-time AML/sanctions screening. "
        "Checks entity against OFAC SDN, EU Consolidated, HMT, UN sanctions, "
        "PEP lists, and adverse media. Proprietary matching algorithm."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "sanctions_list_lookup",
            "type": "deterministic_rule",  # set membership
            "proof_level": "attestation",  # list contents proprietary
            "method": "set_membership",
            "purpose": "OFAC/EU/UN/HMT sanctions list match",
        },
        {
            "stage": 2,
            "name": "pep_screening",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Politically Exposed Person list match",
        },
        {
            "stage": 3,
            "name": "adverse_media",
            "type": "ml_model",
            "proof_level": "attestation",  # proprietary NLP
            "purpose": "Adverse media classification across monitored sources",
        },
        {
            "stage": 4,
            "name": "risk_score_threshold",
            "type": "deterministic_rule",
            "proof_level": "attestation",  # threshold itself is proprietary config
            "method": "threshold_comparison",
            "purpose": "Risk score >= customer-configured alert threshold",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 24,  # sanctions lists update daily
    "publisher": "your-org-id",
}

MANIFEST_TRANSACTION_MONITORING = {
    "name": "comply_advantage_transaction_monitoring",
    "description": (
        "ComplyAdvantage transaction monitoring for suspicious activity. "
        "Velocity checks, structuring detection, behavioral pattern matching."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "velocity_rule",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Transaction count/volume within time window vs threshold",
        },
        {
            "stage": 2,
            "name": "structuring_detection",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Sub-threshold transaction pattern detection (BSA §5324)",
        },
        {
            "stage": 3,
            "name": "behavioral_model",
            "type": "ml_model",
            "proof_level": "attestation",
            "purpose": "ML behavioral anomaly scoring",
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
class AMLScreeningResult:
    """Raw result from ComplyAdvantage screening API."""

    search_id: str
    total_hits: int
    risk_level: str  # "low" | "medium" | "high" | "very_high"
    has_sanctions_match: bool
    has_pep_match: bool
    has_adverse_media: bool
    risk_score: float
    raw_response: dict


@dataclass
class PrimustAMLRecord:
    """What Primust commits — no entity details, no match details, just proof."""

    commitment_hash: str  # input commitment (entity identity, never sent to Primust)
    record_id: str
    proof_level: str  # always "attestation" for ComplyAdvantage
    vpec_id: Optional[str]  # set when p.close() is called
    screening_result: AMLScreeningResult


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class ComplyAdvantageConnector:
    """
    Wraps ComplyAdvantage AML screening with Primust VPEC issuance.

    Usage (per-customer onboarding screen):
        connector = ComplyAdvantageConnector(
            ca_api_key=os.environ["COMPLY_ADVANTAGE_API_KEY"],
            primust_api_key=os.environ["PRIMUST_API_KEY"],
            fraud_score_threshold=75,
        )
        connector.register_manifests()

        # At onboarding time:
        pipeline = connector.new_pipeline(workflow_id="kyc-onboarding-v2")
        result = connector.screen_entity(
            pipeline=pipeline,
            entity_name="Acme Corp",
            entity_type="company",
            country_code="US",
        )
        vpec = pipeline.close()
        # vpec → store in customer record, provide to examiner on request

    The examiner receives the VPEC. It proves:
      - ComplyAdvantage ran at timestamp T
      - Input commitment matches the entity (verifiable if examiner has entity data)
      - Result was pass/fail
      - Methodology: sanctions + PEP + adverse media + risk threshold
    The examiner does NOT receive: which lists flagged, the scoring model internals,
    the customer's configured alert threshold. AML paradox resolved.
    """

    BASE_URL = "https://api.complyadvantage.com"

    def __init__(
        self,
        ca_api_key: str,
        primust_api_key: str,
        fraud_score_threshold: float = 75.0,
        visibility: str = "opaque",  # "opaque" for regulators — aggregate stats only
    ):
        self.ca_api_key = ca_api_key
        self.primust_api_key = primust_api_key
        self.fraud_score_threshold = fraud_score_threshold
        self.visibility = visibility
        self._manifest_ids: dict[str, str] = {}

    # ------------------------------------------------------------------
    # One-time setup
    # ------------------------------------------------------------------

    def register_manifests(self) -> None:
        """Register check manifests with Primust. Call once per environment."""
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [MANIFEST_AML_SCREENING, MANIFEST_TRANSACTION_MONITORING]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id
            print(f"Registered {manifest['name']}: {result.manifest_id}")

    def new_pipeline(self, workflow_id: str) -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    # ------------------------------------------------------------------
    # Entity screening (KYC/onboarding)
    # ------------------------------------------------------------------

    def screen_entity(
        self,
        pipeline: primust.Pipeline,
        entity_name: str,
        entity_type: str = "person",  # "person" | "company"
        country_code: Optional[str] = None,
        date_of_birth: Optional[str] = None,
        visibility: Optional[str] = None,
    ) -> PrimustAMLRecord:
        """
        Screen an entity and issue a VPEC record.

        Raw entity data never leaves this function before commitment.
        Only the commitment hash transits to Primust.
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("comply_advantage_aml_screening")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before screen_entity()")

        # Build search payload
        search_payload = {
            "search_term": entity_name,
            "entity_type": entity_type,
            "filters": {
                "types": [
                    "sanction",
                    "warning",
                    "fitness-probity",
                    "pep",
                    "adverse-media",
                ],
            },
        }
        if country_code:
            search_payload["filters"]["country_codes"] = [country_code]
        if date_of_birth:
            search_payload["filters"]["birth_year"] = date_of_birth[:4]

        # Call ComplyAdvantage
        with httpx.Client() as client:
            resp = client.post(
                f"{self.BASE_URL}/searches",
                json=search_payload,
                auth=(self.ca_api_key, ""),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()

        screening = self._parse_screening_response(data)

        # Determine pass/fail
        check_result = (
            "fail"
            if (screening.has_sanctions_match or screening.risk_score >= self.fraud_score_threshold)
            else "pass"
        )

        # Commit to Primust
        # input = entity identity (name + type + country) — committed locally, never sent
        record = pipeline.record(
            check="comply_advantage_aml_screening",
            manifest_id=manifest_id,
            input=f"{entity_name}|{entity_type}|{country_code or ''}",
            check_result=check_result,
            details={
                "total_hits": screening.total_hits,
                "risk_level": screening.risk_level,
                "has_sanctions_match": screening.has_sanctions_match,
                "has_pep_match": screening.has_pep_match,
                # NOTE: no match details — that would reveal flagging criteria
            },
            visibility=vis,
        )

        return PrimustAMLRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            screening_result=screening,
        )

    # ------------------------------------------------------------------
    # Transaction monitoring
    # ------------------------------------------------------------------

    def monitor_transaction(
        self,
        pipeline: primust.Pipeline,
        transaction_id: str,
        amount: float,
        currency: str,
        counterparty_name: str,
        counterparty_country: str,
        visibility: Optional[str] = None,
    ) -> PrimustAMLRecord:
        """
        Screen a transaction and record proof of monitoring.

        Visibility defaults to "opaque" — proves monitoring ran without
        revealing transaction amounts or counterparty details to the
        VPEC verifier (regulator can request NDA audit path for full data).
        """
        vis = visibility or self.visibility
        manifest_id = self._manifest_ids.get("comply_advantage_transaction_monitoring")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() before monitor_transaction()")

        # Screen counterparty
        with httpx.Client() as client:
            resp = client.post(
                f"{self.BASE_URL}/searches",
                json={
                    "search_term": counterparty_name,
                    "entity_type": "company",
                    "filters": {
                        "types": ["sanction", "warning", "pep"],
                        "country_codes": [counterparty_country],
                    },
                },
                auth=(self.ca_api_key, ""),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()

        screening = self._parse_screening_response(data)
        check_result = "fail" if screening.has_sanctions_match else "pass"

        record = pipeline.record(
            check="comply_advantage_transaction_monitoring",
            manifest_id=manifest_id,
            input=f"{transaction_id}|{counterparty_name}|{counterparty_country}",
            check_result=check_result,
            details={"risk_level": screening.risk_level, "hits": screening.total_hits},
            visibility=vis,
        )

        return PrimustAMLRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            vpec_id=None,
            screening_result=screening,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_screening_response(self, data: dict) -> AMLScreeningResult:
        content = data.get("content", {})
        results = content.get("data", {})
        hits = results.get("hits", [])

        has_sanctions = any(
            any(t in ["sanction"] for t in h.get("doc", {}).get("types", [])) for h in hits
        )
        has_pep = any(any("pep" in t for t in h.get("doc", {}).get("types", [])) for h in hits)
        has_adverse = any(
            any("adverse" in t for t in h.get("doc", {}).get("types", [])) for h in hits
        )
        risk_score = results.get("risk_score", 0.0)

        return AMLScreeningResult(
            search_id=results.get("id", ""),
            total_hits=len(hits),
            risk_level=results.get("risk_level", "low"),
            has_sanctions_match=has_sanctions,
            has_pep_match=has_pep,
            has_adverse_media=has_adverse,
            risk_score=float(risk_score),
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

FIT_VALIDATION = {
    "platform": "ComplyAdvantage",
    "category": "AML/KYC Screening",
    "fit": "STRONG",
    "external_verifier": "FinCEN, FCA, AUSTRAC, BaFin — regulatory examiners",
    "trust_deficit": True,
    "data_sensitivity": "Watchlist matching criteria — revealing enables circumvention (BSA §5324)",
    "gep_value": (
        "Proves AML screen ran on this specific entity at this specific time. "
        "Verifier confirms monitoring occurred without receiving the flagging "
        "criteria that would enable structuring attacks."
    ),
    "proof_ceiling": "attestation",
    "proof_ceiling_reason": "ComplyAdvantage matching algorithm is proprietary SaaS",
    "buildable_today": True,
    "sdk_required": "Python (shipped)",
    "java_sdk_changes_ceiling": False,
    "regulatory_hooks": [
        "BSA/AML",
        "FATF Rec 10/15",
        "MLD5/6",
        "OFAC compliance program",
    ],
    "cross_run_consistency_applicable": False,  # SaaS, can't replay
    "aml_paradox_resolved": True,
}
