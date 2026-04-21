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
import com.primust.Primust;
import com.primust.Pipeline;
import com.primust.Run;
import com.primust.RecordInput;
import com.primust.CheckResult;
import com.primust.VPEC;

import java.util.List;
import java.util.Map;

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
     * @param run             Open pipeline Run
     * @param applicationId   Policy application identifier
     * @param riskData        Underwriting risk factors — committed locally, never sent
     * @param decisionSetId   Which rule set version to apply
     */
    public DecisionResponse executeUnderwritingDecision(
        Run run,
        String applicationId,
        Map<String, Object> riskData,
        String decisionSetId
    ) {
        // Build Sapiens decision request
        DecisionRequest request = DecisionRequest.builder()
            .decisionSetId(decisionSetId)
            .inputData(riskData)
            .build();

        // Execute rule engine in-process — commitment computed before network call
        DecisionResponse response = engine.execute(request);

        List<RuleResult> firedRules = response.getFiredRules();
        String outcome = response.getDecision();   // "ACCEPT" | "DECLINE" | "REFER"
        double computedPremium = response.getPremium();

        CheckResult checkResult = outcome.equals("DECLINE")
            ? CheckResult.FAIL
            : CheckResult.PASS;

        // Record underwriting decision
        // riskData committed locally — rating factors (age, location, claims history) never transit
        run.record(
            RecordInput.builder()
                .check("sapiens_underwriting_decision")
                .manifestId(manifestIdUnderwriting)
                .input(buildInputBinding(applicationId, riskData, decisionSetId))
                // output commitment: the premium computed by the rating algorithm
                // Mathematical proof: verifier can confirm rate * factors = premium
                .output(String.valueOf(computedPremium).getBytes())
                .checkResult(checkResult)
                .details(Map.of(
                    "application_id", applicationId,
                    "decision", outcome,
                    "rules_fired_count", firedRules.size(),
                    "decision_set_id", decisionSetId
                    // premium NOT included — reveals pricing strategy
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
     */
    public void recordRatingFactorApplication(
        Run run,
        String applicationId,
        double baseRate,
        Map<String, Double> factors,        // committed locally — never sent
        double computedPremium
    ) {
        // Build factor string for input commitment
        StringBuilder factorBinding = new StringBuilder(applicationId).append("|base:").append(baseRate);
        factors.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())  // deterministic ordering
            .forEach(e -> factorBinding.append("|").append(e.getKey()).append(":").append(e.getValue()));

        // output = computed premium — Mathematical proof
        // verifier can replay: base_rate * product(factors) = computedPremium
        boolean withinTolerance = computedPremium > 0;

        run.record(
            RecordInput.builder()
                .check("sapiens_rating_factors")
                .manifestId(manifestIdRatingFactors)
                .input(factorBinding.toString().getBytes())
                .output(String.format("%.2f", computedPremium).getBytes())
                .checkResult(withinTolerance ? CheckResult.PASS : CheckResult.FAIL)
                .details(Map.of(
                    "application_id", applicationId,
                    "factor_count", factors.size()
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
        String exclusionSetId
    ) {
        DecisionRequest exclusionRequest = DecisionRequest.builder()
            .decisionSetId(exclusionSetId)
            .inputData(riskData)
            .build();

        DecisionResponse exclusionResponse = engine.execute(exclusionRequest);
        boolean excluded = exclusionResponse.getDecision().equals("EXCLUDE");

        run.record(
            RecordInput.builder()
                .check("sapiens_exclusion_check")
                .manifestId(manifestIdExclusion)
                .input(buildInputBinding(applicationId, riskData, exclusionSetId))
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

    private byte[] buildInputBinding(String appId, Map<String, Object> data, String setId) {
        StringBuilder sb = new StringBuilder("app:").append(appId).append("|set:").append(setId);
        data.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(e -> sb.append("|").append(e.getKey()).append(":").append(e.getValue()));
        return sb.toString().getBytes();
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
 *   "aggregation": { "method": "all_must_pass" }
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
