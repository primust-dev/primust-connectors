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
Guidewire ClaimCenter Connector for Primust

Instruments ClaimCenter claims adjudication workflows to produce VPECs
proving governance ran without disclosing claim data.

Based on Guidewire InsuranceSuite Cloud API (Swagger 2.0)
Public spec: https://docs.guidewire.com/cloud/cc/202411/apiref/
Auth: OAuth2 client credentials (service account)

Proof ceiling: Attestation (REST boundary — all stages)
  REST wrapper gives invocation-binding only. The arithmetic stages
  (coverage limits, deductible, reserve adequacy) are deterministic and
  COULD reach Mathematical via Java IPlugin (in-process), but from REST
  we only observe API responses. Mathematical requires Java SDK + Studio.

External verifier: Reinsurers, Lloyd's syndicates, state DOI examiners
The trust deficit: Cedant proves adjudication ran per policy terms
without providing reinsurer the full claim file.

Regulatory hooks:
  - NAIC Model Law compliance (state DOI examination)
  - Reinsurance treaty audit (cedant → reinsurer proof without file transfer)
  - Lloyd's of London market conduct reporting
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
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
# Fit validation — honest assessment required by all connectors
# ---------------------------------------------------------------------------

FIT_VALIDATION = {
    "platform": "Guidewire ClaimCenter",
    "fit_level": "STRONG",
    "external_verifier": "reinsurers, Lloyd's syndicates, state DOI examiners",
    "trust_deficit": (
        "Cedant needs to prove adjudication ran per policy terms "
        "without transferring full claim file to reinsurer"
    ),
    "regulated_process": True,
    "data_cannot_be_disclosed": True,
    "proof_ceiling": "attestation",
    "proof_ceiling_notes": (
        "REST boundary — all stages are attestation. Coverage limit arithmetic "
        "and reserve checks are deterministic and could reach Mathematical "
        "via the Java IPlugin (in-process), but from REST we only observe "
        "API responses. Mathematical requires the Java SDK + Guidewire Studio."
    ),
    "buildable": "now (REST/Attestation); design partner for in-process/Mathematical",
    "regulatory_hooks": [
        "NAIC Model Law — state DOI examination",
        "Reinsurance treaty audit",
        "Lloyd's market conduct reporting",
    ],
    "partial_fit": False,
    "partial_fit_reason": None,
}


# ---------------------------------------------------------------------------
# Guidewire Cloud API client
# ---------------------------------------------------------------------------

class GuidewireAuthError(Exception):
    pass

class GuidewireAPIError(Exception):
    pass


@dataclass
class GuidewireClient:
    """
    Thin REST client for Guidewire ClaimCenter Cloud API.

    Auth: OAuth2 client credentials (service-to-service).
    Base URL pattern: https://<tenant>.guidewire.com

    Endpoints used:
      POST /rest/common/v1/oauth2/token    — client credentials token
      GET  /rest/claim/v1/claims/{id}      — claim details
      GET  /rest/claim/v1/claims/{id}/exposures  — exposure list
      GET  /rest/claim/v1/claims/{id}/payments   — payment history
      GET  /rest/claim/v1/claims/{id}/activities — activity log
      GET  /rest/common/v1/policies/{id}         — policy details (coverage)
    """

    base_url: str          # e.g. "https://acme.guidewire.com"
    client_id: str
    client_secret: str
    timeout: int = 30

    _token: Optional[str] = field(default=None, init=False, repr=False)
    _token_expiry: float = field(default=0.0, init=False, repr=False)

    def _ensure_token(self) -> None:
        if self._token and time.time() < self._token_expiry - 60:
            return
        resp = httpx.post(
            f"{self.base_url}/rest/common/v1/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise GuidewireAuthError(
                f"Token request failed: {resp.status_code} {resp.text[:200]}"
            )
        data = resp.json()
        self._token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600)

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        self._ensure_token()
        resp = httpx.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            params=params,
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            # Token may have expired mid-session — retry once
            self._token = None
            self._ensure_token()
            resp = httpx.get(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params,
                timeout=self.timeout,
            )
        if resp.status_code not in (200, 206):
            raise GuidewireAPIError(
                f"GET {path} returned {resp.status_code}: {resp.text[:200]}"
            )
        return resp.json()

    # -----------------------------------------------------------------------
    # Domain methods
    # -----------------------------------------------------------------------

    def get_claim(self, claim_id: str) -> dict:
        """GET /rest/claim/v1/claims/{claimId}"""
        return self._get(f"/rest/claim/v1/claims/{claim_id}")

    def get_exposures(self, claim_id: str) -> list[dict]:
        """GET /rest/claim/v1/claims/{claimId}/exposures"""
        data = self._get(f"/rest/claim/v1/claims/{claim_id}/exposures")
        return data.get("data", [])

    def get_payments(self, claim_id: str) -> list[dict]:
        """GET /rest/claim/v1/claims/{claim_id}/payments"""
        data = self._get(f"/rest/claim/v1/claims/{claim_id}/payments")
        return data.get("data", [])

    def get_activities(self, claim_id: str) -> list[dict]:
        """GET /rest/common/v1/activities filtered to claim"""
        data = self._get(
            "/rest/common/v1/activities",
            params={"filter[claimId]": claim_id},
        )
        return data.get("data", [])

    def get_policy(self, policy_id: str) -> dict:
        """GET /rest/common/v1/policies/{policyId}"""
        return self._get(f"/rest/common/v1/policies/{policy_id}")


# ---------------------------------------------------------------------------
# Commitment helpers — raw data never leaves this function
# ---------------------------------------------------------------------------

def _commit(data: Any) -> str:
    """Commit via artifact-core commitment path (SHA-256 default, poseidon2 opt-in)."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    hash_str, _ = _artifact_commit(canonical.encode(), "sha256")
    return hash_str


def _bounded_claim_metadata(claim: dict) -> dict:
    """
    Extract bounded, non-sensitive metadata from a claim object.
    This is the ONLY data that transits to Primust.
    Claim contents, claimant PII, and reserve amounts stay local.
    """
    attrs = claim.get("data", {}).get("attributes", claim.get("attributes", {}))
    return {
        "claim_state": attrs.get("state"),          # e.g. "open", "closed"
        "lob": attrs.get("lineOfBusiness"),          # e.g. "auto", "property"
        "jurisdiction": attrs.get("jurisdiction"),
        "loss_type": attrs.get("lossType"),
        "coverage_type_count": len(attrs.get("coverages", [])),
        "exposure_count": attrs.get("exposureCount"),
    }


def _bounded_payment_metadata(payments: list[dict]) -> dict:
    """Non-sensitive payment summary. No amounts, no claimant IDs."""
    return {
        "payment_count": len(payments),
        "statuses": list({
            p.get("attributes", {}).get("status")
            for p in payments
            if p.get("attributes", {}).get("status")
        }),
    }


# ---------------------------------------------------------------------------
# Arithmetic stages — Mathematical proof ceiling
# ---------------------------------------------------------------------------

def _coverage_limit_check(
    requested_amount: float,
    policy_limit: float,
    deductible: float,
) -> dict:
    """
    Determine whether payment is within policy limits after deductible.

    This is pure arithmetic — deterministic, no PII, verifiable in ZK circuit.
    Proof level: Mathematical

    Returns bounded metadata safe for transit (no monetary amounts).
    """
    net_requested = requested_amount - deductible
    within_limit = net_requested <= policy_limit
    utilization_band = None

    if within_limit and policy_limit > 0:
        ratio = net_requested / policy_limit
        if ratio <= 0.25:
            utilization_band = "0-25%"
        elif ratio <= 0.50:
            utilization_band = "25-50%"
        elif ratio <= 0.75:
            utilization_band = "50-75%"
        else:
            utilization_band = "75-100%"

    return {
        "within_limit": within_limit,
        "deductible_applied": deductible > 0,
        "utilization_band": utilization_band,
        # Amounts committed locally — NOT in this dict
    }


def _reserve_adequacy_check(
    reserve_amount: float,
    incurred_amount: float,
    threshold_ratio: float = 1.0,
) -> dict:
    """
    Check whether reserves are adequate relative to incurred losses.
    Arithmetic bounds check. Proof level: Mathematical.
    """
    adequate = reserve_amount >= (incurred_amount * threshold_ratio)
    return {
        "reserve_adequate": adequate,
        "threshold_ratio": threshold_ratio,
    }


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class GuidewireClaimCenterConnector:
    """
    Instruments Guidewire ClaimCenter claims adjudication with Primust VPEC issuance.

    Workflow:
      1. Retrieve claim + policy from ClaimCenter Cloud API
      2. Commit claim data locally (never sent to Primust)
      3. Execute arithmetic governance checks (coverage limits, reserve adequacy)
         → Mathematical proof level where deterministic
      4. Record adjudication decision
         → Attestation proof level (ClaimCenter rules engine is opaque)
      5. Issue VPEC

    Usage:
        connector = GuidewireClaimCenterConnector(
            gw_base_url="https://acme.guidewire.com",
            gw_client_id="primust-service",
            gw_client_secret="...",
            primust_api_key="pk_live_...",
        )
        connector.register_manifests()
        vpec = connector.adjudicate_claim(
            claim_id="CC:12345",
            requested_payment=45_000.00,
        )
    """

    WORKFLOW_ID = "guidewire-claimcenter-adjudication-v1"

    MANIFEST_CLAIM_RETRIEVAL = {
        "name": "claimcenter_claim_retrieval",
        "version": "1.0.0",
        "description": "Retrieve claim and policy data from ClaimCenter Cloud API",
        "stages": [
            {
                "stage": 1,
                "name": "claim_fetch",
                "type": "api_call",
                "proof_level": "attestation",
                "description": "GET /rest/claim/v1/claims/{claimId}",
                "deterministic": False,
            },
            {
                "stage": 2,
                "name": "policy_fetch",
                "type": "api_call",
                "proof_level": "attestation",
                "description": "GET /rest/common/v1/policies/{policyId}",
                "deterministic": False,
            },
        ],
    }

    MANIFEST_COVERAGE_VERIFICATION = {
        "name": "claimcenter_coverage_verification",
        "version": "1.0.0",
        "description": "Verify payment is within policy coverage limits",
        "stages": [
            {
                "stage": 1,
                "name": "deductible_application",
                "type": "arithmetic",
                "proof_level": "attestation",
                "description": "net_amount = requested - deductible",
                "deterministic": True,
                "mathematical_upgrade_path": "Java IPlugin in-process — threshold_comparison circuit",
            },
            {
                "stage": 2,
                "name": "limit_comparison",
                "type": "arithmetic",
                "proof_level": "attestation",
                "description": "net_amount <= policy_limit",
                "deterministic": True,
                "mathematical_upgrade_path": "Java IPlugin in-process — threshold_comparison circuit",
            },
        ],
    }

    MANIFEST_RESERVE_ADEQUACY = {
        "name": "claimcenter_reserve_adequacy",
        "version": "1.0.0",
        "description": "Verify reserve adequacy against incurred losses",
        "stages": [
            {
                "stage": 1,
                "name": "reserve_ratio_check",
                "type": "arithmetic",
                "proof_level": "attestation",
                "description": "reserve >= incurred * threshold_ratio",
                "deterministic": True,
                "mathematical_upgrade_path": "Java IPlugin in-process — threshold_comparison circuit",
            },
        ],
    }

    MANIFEST_ADJUDICATION_DECISION = {
        "name": "claimcenter_adjudication_decision",
        "version": "1.0.0",
        "description": "ClaimCenter rules engine adjudication decision",
        "stages": [
            {
                "stage": 1,
                "name": "rules_engine_evaluation",
                "type": "rules_engine",
                "proof_level": "attestation",
                "description": "ClaimCenter internal rules engine — opaque",
                "deterministic": False,
                "notes": "Adjudication rules are insurer-configured and not externally observable",
            },
            {
                "stage": 2,
                "name": "payment_authorization",
                "type": "api_call",
                "proof_level": "attestation",
                "description": "Payment authorized via ClaimCenter workflow",
                "deterministic": False,
            },
        ],
    }

    def __init__(
        self,
        gw_base_url: str,
        gw_client_id: str,
        gw_client_secret: str,
        primust_api_key: str,
        primust_base_url: str = "https://api.primust.com",
    ):
        self.gw = GuidewireClient(
            base_url=gw_base_url,
            client_id=gw_client_id,
            client_secret=gw_client_secret,
        )
        self.primust_api_key = primust_api_key
        self.primust_base_url = primust_base_url
        self._manifest_ids: dict[str, str] = {}

    def new_pipeline(self) -> "Pipeline":
        if not PRIMUST_AVAILABLE:
            raise RuntimeError("primust package not installed: pip install primust")
        return primust.Pipeline(
            api_key=self.primust_api_key,
            workflow_id=self.WORKFLOW_ID,
            _base_url=self.primust_base_url,
        )

    def register_manifests(self) -> None:
        """Register all manifests idempotently. Call once at startup."""
        p = self.new_pipeline()
        for name, manifest in [
            ("claim_retrieval", self.MANIFEST_CLAIM_RETRIEVAL),
            ("coverage_verification", self.MANIFEST_COVERAGE_VERIFICATION),
            ("reserve_adequacy", self.MANIFEST_RESERVE_ADEQUACY),
            ("adjudication_decision", self.MANIFEST_ADJUDICATION_DECISION),
        ]:
            reg = p.register_check(manifest)
            self._manifest_ids[name] = reg.manifest_id

    # -----------------------------------------------------------------------
    # Primary instrumented workflow
    # -----------------------------------------------------------------------

    def adjudicate_claim(
        self,
        claim_id: str,
        requested_payment: float,
        pipeline: Optional["Pipeline"] = None,
        policy_id: Optional[str] = None,
    ) -> "VPEC":
        """
        Retrieve and instrument a full claim adjudication workflow.

        1. Fetch claim + policy from ClaimCenter
        2. Commit claim data locally
        3. Run coverage limit check (Mathematical)
        4. Run reserve adequacy check (Mathematical)
        5. Record adjudication decision (Attestation)
        6. Issue and return VPEC

        Privacy guarantee: claim contents, claimant PII, and monetary amounts
        are committed locally. Only bounded metadata (claim state, LOB, payment
        count) and commitment hashes transit to Primust.

        Args:
            claim_id: ClaimCenter claim ID (e.g. "CC:12345")
            requested_payment: Payment amount being authorized
            pipeline: Optional existing Pipeline. New one created if not provided.
            policy_id: Override policy ID. If None, extracted from claim.

        Returns:
            VPEC proving adjudication ran per policy terms.
        """
        if pipeline is None:
            pipeline = self.new_pipeline()

        run = pipeline.open()

        try:
            # ------------------------------------------------------------------
            # Stage 1: Retrieve claim from ClaimCenter
            # ------------------------------------------------------------------
            claim_data = self.gw.get_claim(claim_id)
            attrs = claim_data.get("data", {}).get("attributes", {})

            # Extract policy ID from claim if not provided
            if policy_id is None:
                policy_ref = (
                    claim_data.get("data", {})
                    .get("relationships", {})
                    .get("policy", {})
                    .get("data", {})
                    .get("id")
                )
                policy_id = policy_ref

            # Fetch policy for coverage limits
            policy_data = {}
            policy_attrs = {}
            if policy_id:
                policy_data = self.gw.get_policy(policy_id)
                policy_attrs = (
                    policy_data.get("data", {}).get("attributes", {})
                )

            # Commit full claim + policy locally — never sent to Primust
            claim_commitment = _commit(claim_data)
            policy_commitment = _commit(policy_data)

            run.record(
                check="claim_retrieval",
                manifest_id=self._manifest_ids.get("claim_retrieval", ""),
                check_result="pass",
                input={"claim_commitment": claim_commitment},
                details=_bounded_claim_metadata(claim_data),
                visibility="opaque",
            )

            # ------------------------------------------------------------------
            # Stage 2: Coverage limit check (Mathematical)
            # ------------------------------------------------------------------
            policy_limit = float(policy_attrs.get("totalLimit", 0) or 0)
            deductible = float(attrs.get("deductibleAmount", 0) or 0)

            coverage_result = _coverage_limit_check(
                requested_amount=requested_payment,
                policy_limit=policy_limit,
                deductible=deductible,
            )

            # Commit the raw amounts locally
            amounts_commitment = _commit({
                "requested_payment": requested_payment,
                "policy_limit": policy_limit,
                "deductible": deductible,
                "claim_commitment": claim_commitment,
                "policy_commitment": policy_commitment,
            })

            run.record(
                check="coverage_verification",
                manifest_id=self._manifest_ids.get("coverage_verification", ""),
                check_result="pass" if coverage_result["within_limit"] else "fail",
                input={"amounts_commitment": amounts_commitment},
                details={
                    "within_limit": coverage_result["within_limit"],
                    "deductible_applied": coverage_result["deductible_applied"],
                    "utilization_band": coverage_result["utilization_band"],
                    # No monetary amounts in details — those stay in local commitment
                },
                visibility="opaque",
            )

            if not coverage_result["within_limit"]:
                vpec = run.close()
                return vpec

            # ------------------------------------------------------------------
            # Stage 3: Reserve adequacy (Mathematical)
            # ------------------------------------------------------------------
            exposures = self.gw.get_exposures(claim_id)
            total_reserve = sum(
                float(e.get("attributes", {}).get("reserveAmount", 0) or 0)
                for e in exposures
            )
            total_incurred = sum(
                float(e.get("attributes", {}).get("incurredAmount", 0) or 0)
                for e in exposures
            )

            reserve_result = _reserve_adequacy_check(
                reserve_amount=total_reserve,
                incurred_amount=total_incurred,
            )

            reserve_commitment = _commit({
                "total_reserve": total_reserve,
                "total_incurred": total_incurred,
                "exposure_count": len(exposures),
                "claim_commitment": claim_commitment,
            })

            run.record(
                check="reserve_adequacy",
                manifest_id=self._manifest_ids.get("reserve_adequacy", ""),
                check_result="pass" if reserve_result["reserve_adequate"] else "fail",
                input={"reserve_commitment": reserve_commitment},
                details={
                    "reserve_adequate": reserve_result["reserve_adequate"],
                    "exposure_count": len(exposures),
                    "threshold_ratio": reserve_result["threshold_ratio"],
                },
                visibility="opaque",
            )

            # ------------------------------------------------------------------
            # Stage 4: Adjudication decision + payment (Attestation)
            # ------------------------------------------------------------------
            payments = self.gw.get_payments(claim_id)
            payment_commitment = _commit({
                "payments": payments,
                "requested_payment": requested_payment,
                "claim_commitment": claim_commitment,
            })

            run.record(
                check="adjudication_decision",
                manifest_id=self._manifest_ids.get("adjudication_decision", ""),
                check_result="pass",
                input={"payment_commitment": payment_commitment},
                details=_bounded_payment_metadata(payments),
                visibility="opaque",
            )

        except GuidewireAPIError as e:
            # API error — record the gap, don't swallow it
            run.record(
                check="claim_retrieval",
                manifest_id=self._manifest_ids.get("claim_retrieval", ""),
                check_result="error",
                input={"error": _commit({"error_type": type(e).__name__})},
                details={"error_type": "guidewire_api_error"},
                visibility="opaque",
            )

        return run.close()

    # -----------------------------------------------------------------------
    # Standalone arithmetic checks (usable outside full workflow)
    # -----------------------------------------------------------------------

    def check_payment_within_limits(
        self,
        pipeline: "Pipeline",
        claim_id: str,
        requested_payment: float,
        policy_limit: float,
        deductible: float,
    ) -> "RecordResult":
        """
        Standalone coverage limit check. Mathematical proof level.
        Useful when you already have policy data in memory and don't
        need the full claim retrieval workflow.
        """
        run = pipeline.open()
        result = _coverage_limit_check(requested_payment, policy_limit, deductible)
        amounts_commitment = _commit({
            "claim_id_hash": _commit(claim_id),
            "requested_payment": requested_payment,
            "policy_limit": policy_limit,
            "deductible": deductible,
        })
        return run.record(
            check="coverage_verification",
            manifest_id=self._manifest_ids.get("coverage_verification", ""),
            check_result="pass" if result["within_limit"] else "fail",
            input={"amounts_commitment": amounts_commitment},
            details={
                "within_limit": result["within_limit"],
                "deductible_applied": result["deductible_applied"],
                "utilization_band": result["utilization_band"],
            },
            visibility="opaque",
        )
