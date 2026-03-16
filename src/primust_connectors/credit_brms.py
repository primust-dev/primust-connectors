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
Primust Connectors: FICO Blaze Advisor + IBM Operational Decision Manager
=========================================================================
Fit: STRONG (fair lending, ECOA, discriminatory treatment)
Verifier: CFPB, state AGs, plaintiff attorneys in fair lending actions
Problem solved: Prove the same underwriting rules applied to every applicant
               without revealing the ruleset that would enable gaming
Proof ceiling (REST/today): Attestation
Proof ceiling (Java SDK, post P10-D): Mathematical — full zero-trust proof
                                      that rules evaluated correctly

Cross-run consistency detection (DECISIONS_v4) is the killer feature here:
"Same input must always produce same output for deterministic checks."
Identical applicant profiles receiving different decisions = discriminatory treatment.
Primust fleet scan detects this automatically from commitment hashes alone,
without ever seeing the applicant data.

FICO Blaze REST API: Decision Management Server (DMS) REST API (v7.3+)
IBM ODM REST API: Decision Service REST API (ODM 8.x+)
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


# ===========================================================================
# FICO BLAZE ADVISOR
# ===========================================================================

BLAZE_MANIFEST_CREDIT_DECISIONING = {
    "name": "fico_blaze_credit_decisioning",
    "description": (
        "FICO Blaze Advisor credit decisioning ruleset. "
        "Deterministic rule evaluation: DTI thresholds, LTV limits, "
        "credit score bands, income verification, policy exclusions."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "credit_score_band",
            "type": "deterministic_rule",
            "proof_level": "attestation",    # → mathematical post-Java SDK
            "method": "threshold_comparison",
            "purpose": "Credit score >= minimum threshold for product tier",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa"],
        },
        {
            "stage": 2,
            "name": "dti_calculation",
            "type": "deterministic_rule",
            "proof_level": "attestation",    # → mathematical post-Java SDK
            "method": "threshold_comparison",
            "formula": "monthly_debt / gross_monthly_income <= max_dti",
            "purpose": "Debt-to-income ratio within policy limits",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa", "cfpb_fcra"],
        },
        {
            "stage": 3,
            "name": "ltv_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "formula": "loan_amount / appraised_value <= max_ltv",
            "purpose": "Loan-to-value ratio within policy limits",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa"],
        },
        {
            "stage": 4,
            "name": "policy_exclusion_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Applicant not in policy exclusion list",
            "regulatory_references": ["cfpb_ecoa", "cfpb_fcra"],
        },
        {
            "stage": 5,
            "name": "final_decision",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Aggregate score >= approval threshold",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 168,
    "publisher": "your-org-id",
}


@dataclass
class BlazeDecisionResult:
    decision: str           # "APPROVE" | "DECLINE" | "REFER"
    decision_score: float
    rules_fired: list[str]  # only available in Java SDK path
    reasons: list[str]
    raw_response: dict


@dataclass
class PrimustDecisionRecord:
    commitment_hash: str
    record_id: str
    proof_level: str
    platform: str
    decision: str           # pass/fail from Primust perspective


class FicoBlazeConnector:
    """
    Wraps FICO Blaze Advisor Decision Management Server REST API.

    TODAY (REST path): Attestation ceiling
    POST-P10-D (Java SDK path): Mathematical ceiling — see BlazeAdvisorJava
                                stub below for what changes

    Fair lending use case:
        Each application run produces a VPEC. Fleet consistency scan
        detects identical applicant profiles receiving different decisions.
        CFPB examination: bank provides Evidence Pack (not applicant files).
        Examiner confirms same rules applied to every application without
        receiving the applicant data. ECOA compliance provable, not asserted.

    Gap codes:
      blaze_api_error (High) — DMS API call failed
      blaze_auth_failure (Critical) — API key rejected
      blaze_service_not_found (High) — Ruleset endpoint not found
      blaze_rule_version_mismatch (Medium) — Unexpected ruleset version
    Framework tags: ['occ_sr_11_7', 'cfpb_ecoa', 'cfpb_fcra']
    """

    def __init__(
        self,
        blaze_server_url: str,   # e.g. "https://blaze-dms.bank.internal"
        blaze_api_key: str,
        primust_api_key: str,
        ruleset_name: str,       # e.g. "MortgageUnderwritingV4"
    ):
        self.blaze_url = blaze_server_url.rstrip("/")
        self.blaze_api_key = blaze_api_key
        self.primust_api_key = primust_api_key
        self.ruleset_name = ruleset_name
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [BLAZE_MANIFEST_CREDIT_DECISIONING]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id

    def new_pipeline(self, workflow_id: str = "credit-decisioning") -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    def evaluate(
        self,
        pipeline: Any,
        application_id: str,
        applicant_data: dict,         # credit score, income, debt, LTV, etc.
        visibility: str = "opaque",   # applicant financials are PII
    ) -> PrimustDecisionRecord:
        """
        Submit application to Blaze DMS and record proof of evaluation.

        applicant_data is committed locally (SHA-256) before anything
        leaves the environment. The commitment hash transits to Primust.
        The actual applicant data never leaves your network.

        Cross-run consistency: Primust fleet scan will automatically flag if
        this application_id or identical input_commitment receives a different
        decision in a future run — discriminatory treatment detection.
        """
        manifest_id = self._manifest_ids.get("fico_blaze_credit_decisioning")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Compute input commitment — applicant data hashed, never sent
        input_commitment = _commit(applicant_data)

        # Call Blaze DMS REST API
        try:
            with httpx.Client() as client:
                resp = client.post(
                    f"{self.blaze_url}/api/v1/decision/{self.ruleset_name}",
                    json={"applicationId": application_id, "data": applicant_data},
                    headers={"Authorization": f"Bearer {self.blaze_api_key}"},
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                gap_type, severity = "blaze_auth_failure", "critical"
            elif e.response.status_code == 404:
                gap_type, severity = "blaze_service_not_found", "high"
            else:
                gap_type, severity = "blaze_api_error", "high"
            record = pipeline.record(
                check="fico_blaze_credit_decisioning",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_type, "severity": severity},
                visibility="opaque",
            )
            return PrimustDecisionRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                platform="fico_blaze",
                decision="ERROR",
            )
        except Exception:
            record = pipeline.record(
                check="fico_blaze_credit_decisioning",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "blaze_api_error", "severity": "high"},
                visibility="opaque",
            )
            return PrimustDecisionRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                platform="fico_blaze",
                decision="ERROR",
            )

        blaze_result = self._parse_response(data)
        check_result = "pass" if blaze_result.decision == "APPROVE" else "fail"

        # Output commitment — decision metadata, not raw scores
        output_commitment = _commit({
            "decision": blaze_result.decision,
            "decision_score": blaze_result.decision_score,
            "reason_count": len(blaze_result.reasons),
        })

        record = pipeline.record(
            check="fico_blaze_credit_decisioning",
            manifest_id=manifest_id,
            input={"input_commitment": input_commitment, "output_commitment": output_commitment},
            check_result=check_result,
            details={
                "application_id": application_id,
                "decision": blaze_result.decision,
                "decision_score": blaze_result.decision_score,
                "reason_count": len(blaze_result.reasons),
                # NOTE: reason codes NOT included — would reveal ruleset internals
            },
            visibility=visibility,
        )

        return PrimustDecisionRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            platform="fico_blaze",
            decision=blaze_result.decision,
        )

    def execute_credit_decision(
        self,
        pipeline: Any,
        application_id: str,
        applicant_data: dict,
    ) -> PrimustDecisionRecord:
        """Convenience wrapper: credit decisioning with opaque visibility."""
        return self.evaluate(
            pipeline=pipeline,
            application_id=application_id,
            applicant_data=applicant_data,
            visibility="opaque",
        )

    def execute_aml_screening(
        self,
        pipeline: Any,
        application_id: str,
        screening_data: dict,
    ) -> PrimustDecisionRecord:
        """Convenience wrapper: AML screening via Blaze ruleset."""
        return self.evaluate(
            pipeline=pipeline,
            application_id=application_id,
            applicant_data=screening_data,
            visibility="opaque",
        )

    def _parse_response(self, data: dict) -> BlazeDecisionResult:
        return BlazeDecisionResult(
            decision=data.get("decision", "DECLINE"),
            decision_score=float(data.get("score", 0)),
            rules_fired=data.get("rulesFired", []),
            reasons=data.get("reasons", []),
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# Java SDK stub — demand-gate for Mathematical proof level
# ---------------------------------------------------------------------------

class BlazeAdvisorJava:
    """
    Java SDK path for FICO Blaze Advisor — Mathematical proof ceiling.

    NOT IMPLEMENTED: Requires Java SDK (P10-D) and in-process Blaze engine access.
    This class exists to document the upgrade path and fail clearly at the demand gate.

    When Java SDK ships:
    - In-process rule execution (no REST call)
    - Poseidon2 commitment of input/output in-process
    - Per-rule manifest auto-population from fired rules
    - Cross-run consistency enforced at Mathematical level
    - ECOA compliance: provable, not attested

    Proof level achieved: MATHEMATICAL
    """

    def __init__(self, *args: Any, **kwargs: Any):
        raise NotImplementedError(
            "BlazeAdvisorJava requires the Java SDK (P10-D). "
            "Use FicoBlazeConnector for Attestation-level REST path. "
            "See BLAZE_JAVA_UPGRADE_NOTE for the Mathematical proof path."
        )


BLAZE_JAVA_UPGRADE_NOTE = """
When Java SDK (P10-D) ships, replace REST call + attestation with:

  // In-process — no network call to Blaze DMS
  import com.fico.blaze.engine.RuleEngine;
  import com.primust.Primust;

  RuleEngine engine = RuleEngine.getInstance(rulesetPath);
  ApplicationData input = ApplicationData.from(applicantData);

  // Open pipeline BEFORE rule execution
  Pipeline p = Primust.builder().apiKey(key).workflowId("credit-v4").build();

  engine.execute(ruleset, input);
  Decision decision = input.getDecision();

  // Now we have in-process access to EVERY rule that fired + its inputs
  // This is the Mathematical proof ceiling path
  p.record(
    RecordInput.builder()
      .check("fico_blaze_credit_decisioning")
      .manifestId(manifestId)
      .input(input.toBytes())         // Poseidon2 committed in-process
      .output(decision.toBytes())     // output commitment
      .checkResult(decision.isApprove() ? CheckResult.PASS : CheckResult.FAIL)
      .build()
  );

  VPEC vpec = p.close();

Proof level achieved: MATHEMATICAL
- Same input MUST produce same output (cross-run consistency enforced)
- Verifier can replay: given the ruleset manifest + input commitment,
  independently confirm output commitment — zero trust in Primust or bank
- ECOA compliance: cross-run consistency scan detects discriminatory treatment
  from commitment hashes alone, without ever seeing applicant data
"""


# ===========================================================================
# IBM OPERATIONAL DECISION MANAGER (ODM)
# ===========================================================================

ODM_MANIFEST_UNDERWRITING = {
    "name": "ibm_odm_underwriting",
    "description": (
        "IBM ODM underwriting decision service. "
        "Executes decision tables and rule flows for loan/insurance underwriting. "
        "getRulesFired() exposes which rules executed — enables manifest auto-population."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "eligibility_rules",
            "type": "deterministic_rule",
            "proof_level": "attestation",     # → mathematical post-Java SDK
            "method": "set_membership",
            "purpose": "Applicant meets product eligibility criteria",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa"],
        },
        {
            "stage": 2,
            "name": "risk_scoring",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Computed risk score within acceptable band",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa"],
        },
        {
            "stage": 3,
            "name": "decision_table_evaluation",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Decision table output meets approval criteria",
            "regulatory_references": ["occ_sr_11_7", "cfpb_ecoa", "dora_eu"],
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 168,
    "publisher": "your-org-id",
}


class IBMODMConnector:
    """
    Wraps IBM ODM Decision Service REST API (ODM 8.x+).

    IBM ODM specific advantage over Blaze:
    When Java SDK ships, IlrContext.getRulesFired() exposes the exact rules
    that fired during execution. This enables AUTOMATIC manifest generation —
    the adapter can register a manifest that lists exactly which rules ran,
    not just the ruleset-level claim. Stronger evidence, less manual work.

    Gap codes:
      odm_api_error (High) — Decision Service call failed
      odm_auth_failure (Critical) — API key rejected
    Framework tags: ['occ_sr_11_7', 'cfpb_ecoa', 'dora_eu']

    REST path today:
      POST /DecisionService/rest/v1/{ruleApp}/{ruleAppVersion}/{ruleSet}/{ruleSetVersion}
      Returns: decision + applied rules summary
    """

    def __init__(
        self,
        odm_server_url: str,
        odm_api_key: str,
        primust_api_key: str,
        rule_app: str,
        rule_app_version: str,
        rule_set: str,
        rule_set_version: str = "latest",
    ):
        self.odm_url = odm_server_url.rstrip("/")
        self.odm_api_key = odm_api_key
        self.primust_api_key = primust_api_key
        self.rule_app = rule_app
        self.rule_app_version = rule_app_version
        self.rule_set = rule_set
        self.rule_set_version = rule_set_version
        self._manifest_ids: dict[str, str] = {}

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [ODM_MANIFEST_UNDERWRITING]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id

    def new_pipeline(self, workflow_id: str = "odm-underwriting") -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    def execute_decision(
        self,
        pipeline: Any,
        request_id: str,
        decision_input: dict,
        visibility: str = "opaque",
    ) -> PrimustDecisionRecord:
        """Execute ODM decision service and record VPEC."""
        manifest_id = self._manifest_ids.get("ibm_odm_underwriting")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        input_commitment = _commit(decision_input)

        endpoint = (
            f"{self.odm_url}/DecisionService/rest/v1"
            f"/{self.rule_app}/{self.rule_app_version}"
            f"/{self.rule_set}/{self.rule_set_version}"
        )

        try:
            with httpx.Client() as client:
                resp = client.post(
                    endpoint,
                    json=decision_input,
                    headers={
                        "Authorization": f"Bearer {self.odm_api_key}",
                        "Content-Type": "application/json",
                    },
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            gap_type = "odm_auth_failure" if e.response.status_code == 401 else "odm_api_error"
            severity = "critical" if gap_type == "odm_auth_failure" else "high"
            record = pipeline.record(
                check="ibm_odm_underwriting",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": gap_type, "severity": severity},
                visibility="opaque",
            )
            return PrimustDecisionRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                platform="ibm_odm",
                decision="ERROR",
            )
        except Exception:
            record = pipeline.record(
                check="ibm_odm_underwriting",
                manifest_id=manifest_id,
                check_result="error",
                input={"input_commitment": input_commitment},
                details={"error_type": "odm_api_error", "severity": "high"},
                visibility="opaque",
            )
            return PrimustDecisionRecord(
                commitment_hash=record.commitment_hash,
                record_id=record.record_id,
                proof_level=record.proof_level,
                platform="ibm_odm",
                decision="ERROR",
            )

        decision = data.get("decision", "DECLINE")
        check_result = "pass" if decision in ("APPROVE", "ACCEPT") else "fail"

        output_commitment = _commit({
            "decision": decision,
            "request_id": request_id,
            "rule_set_version": self.rule_set_version,
        })

        record = pipeline.record(
            check="ibm_odm_underwriting",
            manifest_id=manifest_id,
            input={"input_commitment": input_commitment, "output_commitment": output_commitment},
            check_result=check_result,
            details={
                "request_id": request_id,
                "decision": decision,
                "rule_app": self.rule_app,
                "rule_set_version": self.rule_set_version,
            },
            visibility=visibility,
        )

        return PrimustDecisionRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            platform="ibm_odm",
            decision=decision,
        )


ODM_JAVA_UPGRADE_NOTE = """
When Java SDK (P10-D) ships, ODM gets a unique advantage:

  IlrContext ctx = new IlrContext();
  IlrRuleEngine engine = new IlrRuleEngine(rulesetPath);
  engine.execute(ctx, inputParameters);

  // getRulesFired() — ODM-specific: list of every rule that executed
  List<IlrRuleFiredEvent> firedRules = ctx.getRulesFired();

  // This enables AUTO-MANIFEST GENERATION:
  // The adapter can dynamically register a manifest that includes
  // the exact rules that fired, not just the ruleset-level claim.
  // This is stronger evidence than any other BRMS platform provides.

  p.record(
    RecordInput.builder()
      .check("ibm_odm_underwriting")
      .manifestId(autoGeneratedManifestId)    // includes firedRules
      .input(inputParameters.toBytes())
      .output(decision.toBytes())
      .checkResult(...)
      .build()
  );

  Proof level: MATHEMATICAL
  Bonus: per-rule manifest auto-population from getRulesFired()
  This is the highest-fidelity BRMS integration possible.
"""


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

BLAZE_FIT_VALIDATION = {
    "platform": "FICO Blaze Advisor",
    "category": "Credit Decisioning BRMS",
    "fit": "STRONG",
    "external_verifier": "CFPB, state AGs, plaintiff attorneys (fair lending), OCC examiners",
    "trust_deficit": True,
    "data_sensitivity": (
        "Applicant financial data (PII). Ruleset internals — revealing enables gaming. "
        "Discriminatory treatment evidence — revealing triggers liability."
    ),
    "gep_value": (
        "Proves same ruleset applied to every applicant. Fleet cross-run consistency "
        "scan detects identical profiles receiving different decisions — discriminatory "
        "treatment — from commitment hashes alone, without examiner seeing applicant data. "
        "ECOA/fair housing compliance provable, not asserted."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": "mathematical",
    "cross_run_consistency_applicable": True,  # killer feature for fair lending
    "buildable_today": True,
    "sdk_required_for_mathematical": "Java (P10-D, ~2-3 weeks)",
    "regulatory_hooks": ["ECOA", "Fair Housing Act", "CFPB HMDA", "OCC Model Risk Guidance SR 11-7"],
}

ODM_FIT_VALIDATION = {
    "platform": "IBM Operational Decision Manager",
    "category": "Enterprise BRMS / Underwriting",
    "fit": "STRONG",
    "external_verifier": "OCC, Fed, state insurance regulators, reinsurers",
    "trust_deficit": True,
    "data_sensitivity": (
        "Applicant financial data (PII). Rule logic and decision tables — "
        "revealing enables gaming. Discriminatory treatment evidence."
    ),
    "gep_value": (
        "Same as Blaze, plus: getRulesFired() enables automatic per-rule manifest "
        "generation post-Java SDK. Strongest BRMS evidence fidelity available."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": True,
    "sdk_required_for_mathematical": "Java (P10-D, ~2-3 weeks)",
    "unique_advantage": "getRulesFired() enables auto-manifest — no manual manifest authoring",
    "regulatory_hooks": ["ECOA", "Fair Housing Act", "SR 11-7", "DORA (EU)", "Basel III model risk"],
}
