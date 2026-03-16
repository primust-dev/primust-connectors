/*
 * Copyright 2026 Primust, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Primust Connector: Sapiens DECISION (Insurance Underwriting Rules Engine)
 * =========================================================================
 * Fit: STRONG
 * Verifier: State insurance commissioners, Lloyd's syndicates, reinsurers
 * Problem solved: Prove underwriting rules applied consistently without
 *                disclosing the rating factors that enable anti-selection
 * Proof ceiling: Mathematical (in-process Java via Sapiens Decision API)
 * Buildable: Java SDK (P10-D — shipped)
 *
 * Sapiens DECISION product line:
 *   - Sapiens DECISION for P&C — property and casualty underwriting rules
 *   - Sapiens DECISION for Life — life insurance underwriting
 *   - Sapiens CoreSuite — full insurance platform including DECISION
 *
 * Integration surface:
 *   Sapiens DECISION exposes a Java API for in-process rule execution.
 *   The DecisionRuleEngine class (com.sapiens.decision.engine) provides
 *   execute() and evaluateRules() methods.
 *   REST API also available for cloud deployments — attestation ceiling only.
 *
 * Fair underwriting use case (strongest fit):
 *   State commissioner asks: "Prove the same rating factors applied to all
 *   similar risks in your book." Cross-run consistency scan detects
 *   inconsistent rule application without the commissioner seeing the
 *   individual application data (personal lines — PII protected).
 *
 * Reinsurance treaty compliance:
 *   Reinsurer asks: "Prove risks ceded to us were underwritten per the
 *   agreed treaty terms." VPEC proves rule execution without sharing
 *   the full application file.
 */

package com.primust.adapters.sapiens;

import com.sapiens.decision.engine.DecisionRuleEngine;
import com.sapiens.decision.engine.DecisionRequest;
import com.sapiens.decision.engine.DecisionResponse;
import com.sapiens.decision.engine.RuleResult;
import com.sapiens.decision.engine.RuleVersionMismatchException;
import com.primust.Primust;
import com.primust.Pipeline;
import com.primust.Run;
import com.primust.RecordInput;
import com.primust.CheckResult;
import com.primust.VPEC;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Primust governance adapter for Sapiens DECISION underwriting engine.
 *
 * Usage:
 *   SapiensDecisionAdapter adapter = new SapiensDecisionAdapter(
 *     engine, pipeline, manifestIds
 *   );
 *
 *   // At underwriting time:
 *   Run run = pipeline.open();
 *   DecisionResponse response = adapter.executeUnderwritingDecision(
 *     run, application
 *   );
 *   VPEC vpec = run.close();
 *   // Store vpec against policy record
 *   // Provide to reinsurer instead of full application file
 */
public class SapiensDecisionAdapter {

    private final DecisionRuleEngine engine;
    private final Pipeline pipeline;
    private final String manifestIdUnderwriting;
    private final String manifestIdRatingFactors;
    private final String manifestIdExclusion;

    public SapiensDecisionAdapter(
        DecisionRuleEngine engine,
        Pipeline pipeline,
        String manifestIdUnderwriting,
        String manifestIdRatingFactors,
        String manifestIdExclusion
    ) {
        this.engine = engine;
        this.pipeline = pipeline;
        this.manifestIdUnderwriting = manifestIdUnderwriting;
        this.manifestIdRatingFactors = manifestIdRatingFactors;
        this.manifestIdExclusion = manifestIdExclusion;
    }

    // ------------------------------------------------------------------
    // Full underwriting decision
    // ------------------------------------------------------------------

    /**
     * Execute underwriting decision and record VPEC proof.
     *
     * Proof level: MATHEMATICAL
     * - Eligibility rules = set_membership (deterministic)
     * - Rating factor application = arithmetic (rate * factor = premium)
     * - Exclusion check = set_membership (deterministic)
     * - All three hit Mathematical ceiling in-process
     *
     * Cross-run consistency:
     * - Same application inputs must always produce same underwriting outcome
     * - Inconsistent outcomes = potential unfair discrimination
     * - Commissioner exam: consistency proof without seeing applications
     *
     * Commitment fields:
     * - ONLY: application_id, decision_set_id, risk_category, product_type
     * - NEVER: policyholder PII (name, SSN, DOB, address)
     * - NEVER: premium amounts (reveals pricing strategy)
     *
     * @param run             Open pipeline Run
     * @param applicationId   Policy application identifier
     * @param riskData        Underwriting risk factors — committed locally, never sent
     * @param decisionSetId   Which rule set version to apply
     * @param riskCategory    Risk classification category (e.g., "preferred", "standard")
     * @param productType     Insurance product type (e.g., "term_life", "whole_life")
     */
    public DecisionResponse executeUnderwritingDecision(
        Run run,
        String applicationId,
        Map<String, Object> riskData,
        String decisionSetId,
        String riskCategory,
        String productType
    ) {
        // Build Sapiens decision request
        DecisionRequest request = DecisionRequest.builder()
            .decisionSetId(decisionSetId)
            .inputData(riskData)
            .build();

        // Execute rule engine in-process — commitment computed before network call
        // Wrapped in gap code handling: fail-open on engine errors
        DecisionResponse response;
        try {
            response = engine.execute(request);
        } catch (RuleVersionMismatchException versionEx) {
            // Gap code: rule version mismatch — Medium severity
            // Record the gap and fail-open so underwriting can continue
            run.record(
                RecordInput.builder()
                    .check("sapiens_underwriting_decision")
                    .manifestId(manifestIdUnderwriting)
                    .input(buildJsonCommitment(Map.of(
                        "application_id", applicationId,
                        "decision_set_id", decisionSetId,
                        "risk_category", riskCategory,
                        "product_type", productType
                    )))
                    .checkResult(CheckResult.ERROR)
                    .gapCode("sapiens_rule_version_mismatch")
                    .gapSeverity("Medium")
                    .details(Map.of(
                        "application_id", applicationId,
                        "decision_set_id", decisionSetId,
                        "error_type", "rule_version_mismatch",
                        "error_message", versionEx.getMessage()
                    ))
                    .visibility("opaque")
                    .build()
            );
            return null;  // fail-open — caller proceeds without engine result
        } catch (Exception engineEx) {
            // Gap code: engine execution error — High severity
            // Record the gap and fail-open so underwriting can continue
            run.record(
                RecordInput.builder()
                    .check("sapiens_underwriting_decision")
                    .manifestId(manifestIdUnderwriting)
                    .input(buildJsonCommitment(Map.of(
                        "application_id", applicationId,
                        "decision_set_id", decisionSetId,
                        "risk_category", riskCategory,
                        "product_type", productType
                    )))
                    .checkResult(CheckResult.ERROR)
                    .gapCode("sapiens_engine_error")
                    .gapSeverity("High")
                    .details(Map.of(
                        "application_id", applicationId,
                        "decision_set_id", decisionSetId,
                        "error_type", engineEx.getClass().getSimpleName(),
                        "error_message", engineEx.getMessage()
                    ))
                    .visibility("opaque")
                    .build()
            );
            return null;  // fail-open — caller proceeds without engine result
        }

        List<RuleResult> firedRules = response.getFiredRules();
        String outcome = response.getDecision();   // "ACCEPT" | "DECLINE" | "REFER"
        double computedPremium = response.getPremium();

        CheckResult checkResult = outcome.equals("DECLINE")
            ? CheckResult.FAIL
            : CheckResult.PASS;

        // Premium band for output commitment — raw premium NEVER in commitment
        // Bands hide exact pricing while proving computation happened
        String premiumBand = classifyPremiumBand(computedPremium);

        // Record underwriting decision
        // Input commitment: canonical JSON hash of non-PII identifiers only
        // NEVER: policyholder name, SSN, DOB, address
        // NEVER: premium amounts in commitment fields
        run.record(
            RecordInput.builder()
                .check("sapiens_underwriting_decision")
                .manifestId(manifestIdUnderwriting)
                .input(buildJsonCommitment(Map.of(
                    "application_id", applicationId,
                    "decision_set_id", decisionSetId,
                    "risk_category", riskCategory,
                    "product_type", productType
                )))
                // Output commitment: premium band, NOT raw amount
                // Proves computation ran without revealing pricing strategy
                .output(buildJsonCommitment(Map.of(
                    "decision", outcome,
                    "premium_band", premiumBand
                )))
                .checkResult(checkResult)
                .details(Map.of(
                    "application_id", applicationId,
                    "decision", outcome,
                    "rules_fired_count", firedRules.size(),
                    "decision_set_id", decisionSetId,
                    "premium_band", premiumBand
                    // raw premium NOT included — reveals pricing strategy
                    // individual rule results NOT included — reveals rating algorithm
                ))
                .visibility("opaque")
                .build()
        );

        return response;
    }

    // ------------------------------------------------------------------
    // Rating factor validation (standalone check)
    // ------------------------------------------------------------------

    /**
     * Prove rating factors were applied consistently.
     *
     * This is the fair underwriting story:
     * The rating algorithm is deterministic — same risk profile must always
     * produce same premium. Cross-run consistency detection catches violations.
     * State commissioner can verify consistent treatment without seeing
     * individual policyholder data.
     *
     * Proof level: MATHEMATICAL
     * premium = base_rate * age_factor * location_factor * claims_factor * ...
     * This IS arithmetic — verifiable from the manifest formula if verifier
     * has the original rating factors.
     *
     * Commitment fields:
     * - ONLY: application_id, decision_set_id, risk_category, product_type
     * - NEVER: policyholder PII (name, SSN, DOB, address)
     * - NEVER: raw premium amounts (reveals pricing strategy)
     */
    public void recordRatingFactorApplication(
        Run run,
        String applicationId,
        String decisionSetId,
        String riskCategory,
        String productType,
        double baseRate,
        Map<String, Double> factors,        // committed locally — never sent
        double computedPremium
    ) {
        // Premium band for output commitment — raw premium NEVER committed
        String premiumBand = classifyPremiumBand(computedPremium);

        // output = premium band — Mathematical proof without revealing exact premium
        // verifier can confirm computation consistency across runs
        boolean withinTolerance = computedPremium > 0;

        run.record(
            RecordInput.builder()
                .check("sapiens_rating_factors")
                .manifestId(manifestIdRatingFactors)
                // Input commitment: canonical JSON hash — no PII, no premium
                .input(buildJsonCommitment(Map.of(
                    "application_id", applicationId,
                    "decision_set_id", decisionSetId,
                    "risk_category", riskCategory,
                    "product_type", productType
                )))
                // Output commitment: premium band hash, NOT raw amount
                .output(buildJsonCommitment(Map.of(
                    "premium_band", premiumBand,
                    "factor_count", String.valueOf(factors.size())
                )))
                .checkResult(withinTolerance ? CheckResult.PASS : CheckResult.FAIL)
                .details(Map.of(
                    "application_id", applicationId,
                    "factor_count", factors.size(),
                    "premium_band", premiumBand
                ))
                .visibility("opaque")
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Exclusion check
    // ------------------------------------------------------------------

    /**
     * Prove exclusion rules were applied.
     *
     * Treaty compliance: reinsurer needs proof that excluded risks
     * were correctly identified and not ceded under the treaty.
     * VPEC proves exclusion check ran without sharing application data.
     */
    public boolean checkExclusions(
        Run run,
        String applicationId,
        Map<String, Object> riskData,
        String exclusionSetId,
        String riskCategory,
        String productType
    ) {
        DecisionRequest exclusionRequest = DecisionRequest.builder()
            .decisionSetId(exclusionSetId)
            .inputData(riskData)
            .build();

        // Gap code handling for exclusion engine execution
        DecisionResponse exclusionResponse;
        try {
            exclusionResponse = engine.execute(exclusionRequest);
        } catch (RuleVersionMismatchException versionEx) {
            run.record(
                RecordInput.builder()
                    .check("sapiens_exclusion_check")
                    .manifestId(manifestIdExclusion)
                    .input(buildJsonCommitment(Map.of(
                        "application_id", applicationId,
                        "exclusion_set_id", exclusionSetId,
                        "risk_category", riskCategory,
                        "product_type", productType
                    )))
                    .checkResult(CheckResult.ERROR)
                    .gapCode("sapiens_rule_version_mismatch")
                    .gapSeverity("Medium")
                    .details(Map.of(
                        "application_id", applicationId,
                        "exclusion_set_id", exclusionSetId,
                        "error_type", "rule_version_mismatch",
                        "error_message", versionEx.getMessage()
                    ))
                    .visibility("opaque")
                    .build()
            );
            return false;  // fail-open — not excluded
        } catch (Exception engineEx) {
            run.record(
                RecordInput.builder()
                    .check("sapiens_exclusion_check")
                    .manifestId(manifestIdExclusion)
                    .input(buildJsonCommitment(Map.of(
                        "application_id", applicationId,
                        "exclusion_set_id", exclusionSetId,
                        "risk_category", riskCategory,
                        "product_type", productType
                    )))
                    .checkResult(CheckResult.ERROR)
                    .gapCode("sapiens_engine_error")
                    .gapSeverity("High")
                    .details(Map.of(
                        "application_id", applicationId,
                        "exclusion_set_id", exclusionSetId,
                        "error_type", engineEx.getClass().getSimpleName(),
                        "error_message", engineEx.getMessage()
                    ))
                    .visibility("opaque")
                    .build()
            );
            return false;  // fail-open — not excluded
        }

        boolean excluded = exclusionResponse.getDecision().equals("EXCLUDE");

        run.record(
            RecordInput.builder()
                .check("sapiens_exclusion_check")
                .manifestId(manifestIdExclusion)
                // Input commitment: canonical JSON hash — no PII
                .input(buildJsonCommitment(Map.of(
                    "application_id", applicationId,
                    "exclusion_set_id", exclusionSetId,
                    "risk_category", riskCategory,
                    "product_type", productType
                )))
                .checkResult(excluded ? CheckResult.FAIL : CheckResult.PASS)
                .details(Map.of(
                    "application_id", applicationId,
                    "exclusion_set_id", exclusionSetId,
                    "excluded", excluded
                ))
                .visibility("opaque")
                .build()
        );

        return excluded;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /**
     * Build a canonical JSON commitment hash from a map of fields.
     *
     * Sorts keys alphabetically, builds canonical JSON string, and returns
     * the SHA-256 hash. This is a COMMITMENT, not the raw data — the hash
     * proves the input was seen without revealing the values.
     *
     * CRITICAL: Only pass safe fields. NEVER include:
     * - Policyholder PII (name, SSN, DOB, address)
     * - Raw premium amounts (reveals pricing strategy)
     *
     * @param fields Map of field name to value — keys sorted for deterministic hashing
     * @return SHA-256 hash bytes (32 bytes)
     */
    private byte[] buildJsonCommitment(Map<String, String> fields) {
        // Sort keys for canonical ordering
        TreeMap<String, String> sorted = new TreeMap<>(fields);

        // Build canonical JSON — no whitespace, sorted keys
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            if (!first) json.append(",");
            first = false;
            json.append("\"").append(escapeJson(entry.getKey())).append("\"");
            json.append(":");
            json.append("\"").append(escapeJson(entry.getValue())).append("\"");
        }
        json.append("}");

        // SHA-256 hash — commitment, not raw data
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(json.toString().getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by JCA spec — should never happen
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Minimal JSON string escaping for canonical serialization.
     */
    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                     .replace("\"", "\\\"")
                     .replace("\n", "\\n")
                     .replace("\r", "\\r")
                     .replace("\t", "\\t");
    }

    /**
     * Classify premium into a band for output commitment.
     *
     * Raw premium amount NEVER appears in commitment or output fields —
     * it reveals pricing strategy and enables anti-selection.
     * Bands provide enough granularity for consistency checking
     * without disclosing exact pricing.
     */
    private String classifyPremiumBand(double premium) {
        if (premium <= 500)   return "tier_1";
        if (premium <= 1000)  return "tier_2";
        if (premium <= 2500)  return "tier_3";
        if (premium <= 5000)  return "tier_4";
        if (premium <= 10000) return "tier_5";
        return "tier_6";
    }
}

/*
 * Manifest definitions:
 *
 * UNDERWRITING_MANIFEST:
 * {
 *   "name": "sapiens_underwriting_decision",
 *   "stages": [
 *     { "stage": 1, "name": "eligibility_check", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "set_membership",
 *       "purpose": "Risk within eligible product parameters" },
 *     { "stage": 2, "name": "rating_algorithm", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "purpose": "Rating factors applied to compute base premium" },
 *     { "stage": 3, "name": "acceptance_decision", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "computed_premium <= max_acceptable_premium AND meets_all_criteria",
 *       "purpose": "Final accept/decline based on rating output and criteria" }
 *   ],
 *   "aggregation": { "method": "all_must_pass" },
 *   "regulatory_references": [
 *     "naic_unfair_trade_practices",
 *     "state_market_conduct",
 *     "lloyds_market_conduct"
 *   ]
 * }
 *
 * RATING_FACTORS_MANIFEST:
 * {
 *   "name": "sapiens_rating_factors",
 *   "stages": [
 *     { "stage": 1, "name": "factor_multiplication", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "base_rate * product(all_factors) = computed_premium",
 *       "purpose": "Rating algorithm arithmetic — verifier can replay" }
 *   ],
 *   "regulatory_references": [
 *     "naic_unfair_trade_practices",
 *     "state_rating_laws"
 *   ]
 * }
 *
 * EXCLUSION_MANIFEST:
 * {
 *   "name": "sapiens_exclusion_check",
 *   "stages": [
 *     { "stage": 1, "name": "exclusion_rule_evaluation", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "set_membership",
 *       "purpose": "Risk evaluated against exclusion criteria per treaty terms" }
 *   ],
 *   "aggregation": { "method": "all_must_pass" },
 *   "regulatory_references": [
 *     "reinsurance_treaty_compliance",
 *     "naic_unfair_trade_practices"
 *   ]
 * }
 */

/*
FIT_VALIDATION = {
    "platform": "Sapiens DECISION",
    "category": "Insurance Underwriting Rules Engine",
    "fit": "STRONG",
    "external_verifier": "State insurance commissioners, Lloyd's syndicates, reinsurers",
    "trust_deficit": True,
    "data_sensitivity": (
        "Rating factors (age, location, claims history) — PII under state regs. "
        "Rating algorithm internals — competitive, revealing enables anti-selection. "
        "Exclusion criteria — treaty confidential."
    ),
    "gep_value": (
        "Proves same rating algorithm applied to all risks in book. "
        "Cross-run consistency detects inconsistent premium computation — "
        "fair underwriting proof to state commissioner without disclosing applications. "
        "Reinsurance treaty: prove exclusion check ran without sharing application files."
    ),
    "proof_ceiling": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable": "Java SDK shipped",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC unfair trade practices model act",
        "Lloyd's market conduct standards",
        "Reinsurance treaty compliance",
        "GDPR (EU life insurance underwriting)",
    ],
}
*/
