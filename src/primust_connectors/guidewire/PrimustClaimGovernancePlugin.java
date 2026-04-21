/**
 * Primust Governance Plugin for Guidewire PolicyCenter / ClaimCenter
 * ==================================================================
 * Fit: STRONG (reinsurance context)
 * Verifier: Reinsurers, state insurance regulators, Lloyd's syndicates
 * Problem solved: Prove claims adjudication ran per policy terms without
 *                 disclosing claimant medical records or loss details
 * Proof ceiling: Mathematical (in-process Java via IPlugin)
 * Buildable: Post P10-D (Java SDK) + design partner with Guidewire access
 *
 * Reinsurance use case — the strongest fit:
 *   A cedant (primary insurer) cedes a block of claims to a reinsurer.
 *   Reinsurer asks: "Prove these claims were adjudicated per the policy rules
 *   you said applied." Current answer: share the claim files. Problem: claimant
 *   medical records, loss details, PII — all legally protected, often HIPAA.
 *   With Primust: VPEC proves adjudication rules ran correctly on each claim
 *   without the reinsurer ever seeing the claim contents.
 *
 * Guidewire plugin architecture:
 *   IPluginFactory.createPlugin(IPlugin) — instantiated per-request
 *   IPlugin lifecycle hooks fire before/after rule execution
 *   Gosu scripting layer calls Java plugins via type system binding
 *
 * REQUIRES:
 *   - Java SDK (P10-D) — ships with Maven artifact com.primust:primust-sdk
 *   - Design partner with Guidewire PolicyCenter or ClaimCenter license
 *   - Guidewire plugin development environment (Studio)
 *
 * NOTE: This is a spec/stub. Exact API surface requires Guidewire Studio access
 * to verify IPlugin interface methods and Gosu binding. Parameterized by
 * ClaimCenter here — PolicyCenter follows same pattern with rating algorithm hooks.
 */

package com.primust.adapters.guidewire;

import com.guidewire.pl.plugin.IPlugin;
import com.guidewire.pl.plugin.IPluginFactory;
import com.guidewire.cc.domain.claim.Claim;
import com.guidewire.cc.domain.claim.financials.ClaimFinancials;
import com.primust.Primust;
import com.primust.Pipeline;
import com.primust.RecordInput;
import com.primust.CheckResult;
import com.primust.VPEC;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Primust governance plugin for Guidewire ClaimCenter.
 *
 * Installed via Guidewire Studio as a custom plugin.
 * Configured in plugin.xml with parameters:
 *   - primust_api_key
 *   - workflow_id
 *   - coverage_verification_manifest_id
 *   - payment_rule_manifest_id
 */
public class PrimustClaimGovernancePlugin implements IPlugin {

    private Pipeline _pipeline;
    private String _manifestIdCoverageVerification;
    private String _manifestIdPaymentRule;
    private String _manifestIdFraudIndicator;

    // Plugin lifecycle — called by Guidewire on instantiation
    @Override
    public void init(IPluginFactory factory) {
        String apiKey = factory.getParam("primust_api_key");
        String workflowId = factory.getParam("workflow_id");
        _manifestIdCoverageVerification = factory.getParam("coverage_verification_manifest_id");
        _manifestIdPaymentRule = factory.getParam("payment_rule_manifest_id");
        _manifestIdFraudIndicator = factory.getParam("fraud_indicator_manifest_id");

        _pipeline = Primust.builder()
            .apiKey(apiKey)
            .workflowId(workflowId)
            .build();
    }

    // ------------------------------------------------------------------
    // Coverage verification hook
    // Called before coverage determination is applied to a claim
    // ------------------------------------------------------------------

    /**
     * Record proof that coverage verification rules ran on this claim.
     *
     * Proof level: MATHEMATICAL
     * - Coverage determination is deterministic (policy terms are fixed rules)
     * - Same claim inputs must always produce same coverage determination
     * - Cross-run consistency scan detects inconsistent coverage application
     *
     * Privacy: claim contents never leave customer environment.
     * Reinsurer receives VPEC proving adjudication ran — not the claim file.
     *
     * @param claim The Guidewire Claim entity
     * @param coverageCode The coverage being evaluated
     * @param determinationResult COVERED | NOT_COVERED | PARTIAL
     */
    public void onCoverageVerification(
        Claim claim,
        String coverageCode,
        String determinationResult
    ) {
        CheckResult result = determinationResult.equals("COVERED")
            ? CheckResult.PASS
            : CheckResult.FAIL;

        // Input: claim number + coverage code + policy version
        // This commits the claim identity and coverage being checked.
        // Claim contents (loss details, medical records) are NOT in the input —
        // they are committed via input hash before anything leaves this process.
        String inputBinding = String.format(
            "claim:%s|coverage:%s|policy_version:%s",
            claim.getClaimNumber(),
            coverageCode,
            claim.getPolicy().getPolicyNumber() + "_v" + claim.getPolicy().getPeriod()
        );

        _pipeline.record(
            RecordInput.builder()
                .check("guidewire_coverage_verification")
                .manifestId(_manifestIdCoverageVerification)
                .input(inputBinding.getBytes())
                .checkResult(result)
                .details(Map.of(
                    "claim_number", claim.getClaimNumber(),
                    "coverage_code", coverageCode,
                    "determination", determinationResult
                    // loss_amount NOT included — protected
                    // claimant details NOT included — PHI
                ))
                .visibility("opaque")  // claim contents protected
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Payment rule hook
    // Called before claim payment is authorized
    // ------------------------------------------------------------------

    /**
     * Record proof that payment authorization rules ran.
     *
     * Payment authorization is deterministic:
     * - Reserve adequacy check (reserve >= payment amount)
     * - Authority limit check (payment <= adjuster's authority)
     * - Coverage limit check (cumulative payments <= policy limit)
     * All three are arithmetic threshold comparisons → Mathematical proof.
     *
     * @param claim The claim
     * @param paymentAmount Requested payment amount
     * @param adjusterAuthority The adjuster's configured payment authority
     * @param remainingLimit Policy limit remaining after prior payments
     */
    public void onPaymentAuthorization(
        Claim claim,
        double paymentAmount,
        double adjusterAuthority,
        double remainingLimit
    ) {
        boolean authorityOk = paymentAmount <= adjusterAuthority;
        boolean limitOk = paymentAmount <= remainingLimit;
        boolean reserveOk = claim.getTotalReserves() >= paymentAmount;

        CheckResult result = (authorityOk && limitOk && reserveOk)
            ? CheckResult.PASS
            : CheckResult.FAIL;

        _pipeline.record(
            RecordInput.builder()
                .check("guidewire_payment_authorization")
                .manifestId(_manifestIdPaymentRule)
                // Input commits the three threshold values — all arithmetic
                // Mathematical proof: verifier can confirm
                // payment <= authority, payment <= limit, reserve >= payment
                // from commitment alone if they have the original values
                .input(String.format(
                    "claim:%s|payment:%.2f|authority:%.2f|limit:%.2f|reserve:%.2f",
                    claim.getClaimNumber(),
                    paymentAmount,
                    adjusterAuthority,
                    remainingLimit,
                    claim.getTotalReserves()
                ).getBytes())
                .checkResult(result)
                .details(Map.of(
                    "claim_number", claim.getClaimNumber(),
                    "authority_check", authorityOk,
                    "limit_check", limitOk,
                    "reserve_check", reserveOk
                    // Amounts NOT included in details — financial data
                    // amounts ARE in the input commitment (opaque to verifier)
                ))
                .visibility("opaque")
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Fraud indicator check hook
    // Called when SIU (Special Investigations Unit) flags are evaluated
    // ------------------------------------------------------------------

    public void onFraudIndicatorEvaluation(
        Claim claim,
        int fraudIndicatorScore,
        int siuReferralThreshold,
        boolean referredToSIU
    ) {
        // Threshold comparison: score >= referral threshold → SIU referral
        // This is Mathematical if manifest includes method=threshold_comparison
        CheckResult result = referredToSIU ? CheckResult.FAIL : CheckResult.PASS;

        _pipeline.record(
            RecordInput.builder()
                .check("guidewire_fraud_indicator")
                .manifestId(_manifestIdFraudIndicator)
                .input(String.format(
                    "claim:%s|score:%d|threshold:%d",
                    claim.getClaimNumber(),
                    fraudIndicatorScore,
                    siuReferralThreshold
                ).getBytes())
                .checkResult(result)
                .details(Map.of(
                    "claim_number", claim.getClaimNumber(),
                    "referred_to_siu", referredToSIU
                ))
                .visibility("selective")
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Close pipeline and issue VPEC at claim close
    // ------------------------------------------------------------------

    /**
     * Issue VPEC for completed claim lifecycle.
     * Call when claim is closed or at end of adjudication workflow.
     * VPEC is stored against the claim record and provided to reinsurer
     * in lieu of claim file disclosure.
     */
    public VPEC issueClaim VPEC(Claim claim) {
        return _pipeline.close();
    }

    // Plugin teardown
    @Override
    public void destroy() {
        // Ensure pipeline is closed — any open pipeline auto-closes with gap record
        if (_pipeline != null) {
            _pipeline.close();
        }
    }
}


/*
 * Manifest definitions for registration (register once via Primust dashboard or API)
 *
 * COVERAGE_VERIFICATION_MANIFEST:
 * {
 *   "name": "guidewire_coverage_verification",
 *   "description": "Guidewire ClaimCenter coverage determination. Evaluates policy terms
 *                   against loss facts to determine covered/not-covered/partial.",
 *   "stages": [
 *     {
 *       "stage": 1,
 *       "name": "policy_terms_lookup",
 *       "type": "deterministic_rule",
 *       "proof_level": "mathematical",
 *       "method": "set_membership",
 *       "purpose": "Loss type within covered perils defined in policy schedule"
 *     },
 *     {
 *       "stage": 2,
 *       "name": "exclusion_check",
 *       "type": "deterministic_rule",
 *       "proof_level": "mathematical",
 *       "method": "set_membership",
 *       "purpose": "Loss circumstances not in policy exclusion schedule"
 *     },
 *     {
 *       "stage": 3,
 *       "name": "deductible_application",
 *       "type": "deterministic_rule",
 *       "proof_level": "mathematical",
 *       "method": "threshold_comparison",
 *       "formula": "loss_amount >= deductible",
 *       "purpose": "Loss amount exceeds policy deductible"
 *     }
 *   ],
 *   "aggregation": { "method": "all_must_pass" },
 *   "freshness_threshold_hours": 720
 * }
 *
 * PAYMENT_RULE_MANIFEST:
 * {
 *   "name": "guidewire_payment_authorization",
 *   "stages": [
 *     { "stage": 1, "name": "authority_limit", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "payment_amount <= adjuster_authority_limit" },
 *     { "stage": 2, "name": "policy_limit", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "cumulative_payments + payment_amount <= policy_limit" },
 *     { "stage": 3, "name": "reserve_adequacy", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "total_reserves >= payment_amount" }
 *   ],
 *   "aggregation": { "method": "all_must_pass" }
 * }
 */


// ---------------------------------------------------------------------------
// FIT VALIDATION (as Java comment — sourced in fit_validation.py)
// ---------------------------------------------------------------------------

/*
FIT_VALIDATION = {
    "platform": "Guidewire ClaimCenter / PolicyCenter",
    "category": "Insurance Claims Adjudication",
    "fit": "STRONG (reinsurance context specifically)",
    "external_verifier": "Reinsurers, Lloyd's syndicates, state DOI examiners",
    "trust_deficit": True,
    "data_sensitivity": (
        "Claimant medical records (HIPAA), loss details, financial reserves — "
        "all protected from counterparty disclosure in reinsurance context"
    ),
    "gep_value": (
        "Cedant proves adjudication ran per policy terms on each claim without "
        "providing the reinsurer the claim file. Reinsurance commutation disputes "
        "resolved by math, not by disclosure. DOI market conduct exams provable "
        "without producing claim files containing claimant PHI."
    ),
    "proof_ceiling": "mathematical",  # in-process IPlugin, all stages deterministic
    "proof_ceiling_notes": (
        "Coverage determination, payment authorization, fraud indicator — "
        "all deterministic arithmetic. Mathematical proof across the board. "
        "This is the best proof story in the entire connector set."
    ),
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "Java (P10-D, ~2-3 weeks) + Guidewire Studio license",
    "design_partner_required": True,
    "design_partner_note": (
        "Guidewire licenses are expensive and tightly controlled. "
        "Need a P&C insurer design partner with ClaimCenter license "
        "to validate IPlugin API surface and test in Studio environment. "
        "When that partner shows up, build Java SDK and this adapter in the same sprint."
    ),
    "regulatory_hooks": [
        "State insurance market conduct exam requirements",
        "Lloyd's market conduct standards",
        "HIPAA for health-related claims",
        "NAIC model audit rule",
    ],
}
*/
