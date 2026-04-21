// Primust Connector: Sapiens ALIS (L&AH Insurance Platform)
// ===========================================================
// Fit: STRONG
// Verifier: State insurance departments, reinsurers, SEC (variable products)
// Proof ceiling: Mathematical (C# in-process via Sapiens ALIS .NET API)
// Buildable: C# SDK (P10-E — shipped)
//
// Sapiens ALIS is the Life, Annuity, and Health line of Sapiens.
// Distinct from Sapiens DECISION (which is the Java rules engine).
// ALIS is a full L&AH policy administration system built on .NET.
//
// Additional regulatory angle vs P&C platforms:
//   Variable product disclosures — SEC-regulated annuities require proof
//   of suitability assessment. Prove the suitability check ran on this
//   customer without disclosing their full financial profile.
//   FINRA Rule 2111 / Regulation Best Interest compliance.
//
// ALIS .NET API:
//   Sapiens.ALIS.Core namespace — policy lifecycle objects
//   Sapiens.ALIS.Rules namespace — underwriting rules execution
//   Sapiens.ALIS.Extensions namespace — plugin/extension points

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Sapiens.ALIS.Core;
using Sapiens.ALIS.Rules;
using Sapiens.ALIS.Extensions;
using Primust;

namespace Primust.Adapters.Sapiens
{
    /// <summary>
    /// Primust governance extension for Sapiens ALIS (Life, Annuity, Health).
    ///
    /// Registration in ALIS Extension Pipeline (extensions.config):
    ///   ExtensionPoint: PolicyIssuance.Underwriting.AfterDecision
    ///   ExtensionPoint: Annuity.Suitability.AfterAssessment
    ///   ExtensionPoint: Claims.Processing.AfterBenefitDetermination
    ///   ExtensionPoint: Claims.Payment.BeforePayment
    /// </summary>
    public class PrimustAlisExtension : IAlisExtension
    {
        private readonly Pipeline _pipeline;
        private readonly string _underwritingManifestId;
        private readonly string _suitabilityManifestId;
        private readonly string _benefitManifestId;
        private readonly string _paymentManifestId;

        public PrimustAlisExtension(
            Pipeline pipeline,
            string underwritingManifestId,
            string suitabilityManifestId,
            string benefitManifestId,
            string paymentManifestId)
        {
            _pipeline = pipeline;
            _underwritingManifestId = underwritingManifestId;
            _suitabilityManifestId = suitabilityManifestId;
            _benefitManifestId = benefitManifestId;
            _paymentManifestId = paymentManifestId;
        }

        // ------------------------------------------------------------------
        // Life/Health underwriting decision
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired after ALIS underwriting rules produce a life/health decision.
        ///
        /// Proof level: MATHEMATICAL
        /// Non-discrimination compliance: ADA/GINA prohibit underwriting
        /// on certain health conditions. Cross-run consistency scan detects
        /// if identical health profiles received different underwriting outcomes —
        /// potential discriminatory treatment.
        ///
        /// State exam: prove consistent underwriting without disclosing
        /// applicant health data. GINA compliance without producing
        /// the genetic information that was evaluated.
        /// </summary>
        public async Task OnUnderwritingDecisionAsync(
            IAlisUnderwritingContext context,
            UnderwritingDecision decision)
        {
            var run = _pipeline.Open();

            try
            {
                var checkResult = decision.Outcome == UnderwritingOutcome.Approved
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                // Health data committed locally — NEVER transits to Primust
                // Only the commitment hash + structured metadata sent
                var inputBinding = BuildUnderwritingInputBinding(context, decision);

                await run.RecordAsync(new RecordInput
                {
                    Check = "sapiens_alis_underwriting",
                    ManifestId = _underwritingManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(inputBinding),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["application_id"] = context.ApplicationId,
                        ["product_code"] = context.ProductCode,
                        ["underwriting_class"] = decision.UnderwritingClass,
                        ["table_rating"] = decision.TableRating,
                        // health conditions NOT included — GINA/ADA protected
                        // premium NOT included — reveals rating strategy
                    },
                    Visibility = "opaque"
                });

                var vpec = await run.CloseAsync();
                context.SetAttribute("PrimustVPEC", vpec.VpecId);
            }
            catch (Exception) { await run.CloseAsync(); }
        }

        // ------------------------------------------------------------------
        // Annuity suitability assessment (FINRA 2111 / Reg BI)
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired after ALIS suitability assessment for variable annuity sales.
        ///
        /// Strongest unique fit vs P&C platforms — SEC/FINRA regulated.
        ///
        /// Proof level: MATHEMATICAL for threshold stages
        ///   Risk tolerance score >= product risk level (arithmetic)
        ///   Investment horizon >= product minimum horizon (arithmetic)
        ///   Liquid net worth >= product minimum (arithmetic)
        ///   All three deterministic threshold checks → Mathematical
        ///
        /// Reg BI compliance:
        ///   FINRA auditor asks: "Prove suitability was assessed for all
        ///   annuity sales." VPEC proves assessment ran without disclosing
        ///   customer's full financial profile (net worth, investment holdings).
        ///
        /// GDPR Art. 22 (EU):
        ///   Prove the automated suitability check ran, not a human override.
        /// </summary>
        public async Task OnSuitabilityAssessmentAsync(
            IAlisCustomerContext context,
            SuitabilityAssessmentResult assessment)
        {
            var run = _pipeline.Open();

            try
            {
                // All three suitability checks are arithmetic threshold comparisons
                // Mathematical proof ceiling for each
                bool riskOk = assessment.CustomerRiskScore >= assessment.ProductMinRiskScore;
                bool horizonOk = assessment.InvestmentHorizonYears >= assessment.ProductMinHorizonYears;
                bool liquidityOk = assessment.LiquidNetWorth >= assessment.ProductMinLiquidNetWorth;

                var overallOk = riskOk && horizonOk && liquidityOk;
                var checkResult = overallOk ? CheckResult.Pass : CheckResult.Fail;

                // Input commits customer financial profile — committed locally
                // Financial profile values (net worth, income) never transit
                var inputBinding = string.Format(
                    "customer:{0}|product:{1}|risk:{2}|horizon:{3}|liquidity:{4}",
                    context.CustomerId,
                    assessment.ProductCode,
                    assessment.CustomerRiskScore,
                    assessment.InvestmentHorizonYears,
                    assessment.LiquidNetWorth
                );

                await run.RecordAsync(new RecordInput
                {
                    Check = "sapiens_alis_suitability",
                    ManifestId = _suitabilityManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(inputBinding),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["customer_id"] = context.CustomerId,
                        ["product_code"] = assessment.ProductCode,
                        ["risk_check"] = riskOk,
                        ["horizon_check"] = horizonOk,
                        ["liquidity_check"] = liquidityOk,
                        ["assessment_version"] = assessment.AssessmentVersion,
                        // actual financial values NOT included
                    },
                    Visibility = "selective"   // check results visible, financial values opaque
                });

                await run.CloseAsync();
            }
            catch (Exception) { await run.CloseAsync(); }
        }

        // ------------------------------------------------------------------
        // Health/Life benefit determination
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired after ALIS determines benefit eligibility on a claim.
        /// Health plan: prove benefit determination ran per plan documents.
        /// State insurance exam: consistent benefit application across book.
        /// </summary>
        public async Task OnBenefitDeterminationAsync(
            IAlisClaimContext context,
            BenefitDetermination determination)
        {
            var run = _pipeline.Open();

            try
            {
                await run.RecordAsync(new RecordInput
                {
                    Check = "sapiens_alis_benefit_determination",
                    ManifestId = _benefitManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(
                        $"claim:{context.ClaimId}|benefit:{determination.BenefitCode}|plan:{context.PlanVersion}"
                    ),
                    CheckResult = determination.IsApproved ? CheckResult.Pass : CheckResult.Fail,
                    Details = new Dictionary<string, object>
                    {
                        ["claim_id"] = context.ClaimId,
                        ["benefit_code"] = determination.BenefitCode,
                        ["is_approved"] = determination.IsApproved,
                        ["plan_version"] = context.PlanVersion,
                    },
                    Visibility = "opaque"   // medical data is PHI
                });

                await run.CloseAsync();
            }
            catch (Exception) { await run.CloseAsync(); }
        }

        // ------------------------------------------------------------------
        // Internal helpers
        // ------------------------------------------------------------------

        private string BuildUnderwritingInputBinding(
            IAlisUnderwritingContext ctx,
            UnderwritingDecision decision)
        {
            // Sort health factors deterministically for cross-run consistency
            var factors = new SortedDictionary<string, object>();
            foreach (var factor in ctx.UnderwritingFactors)
                factors[factor.Key] = factor.Value;

            var sb = new System.Text.StringBuilder();
            sb.Append($"app:{ctx.ApplicationId}|product:{ctx.ProductCode}|table:{decision.TableRating}");
            foreach (var kv in factors)
                sb.Append($"|{kv.Key}:{kv.Value}");
            return sb.ToString();
        }
    }
}

/*
FIT_VALIDATION = {
    "platform": "Sapiens ALIS",
    "category": "Life, Annuity, Health Insurance Platform",
    "fit": "STRONG",
    "external_verifier": (
        "State insurance departments, SEC/FINRA (variable products), "
        "CMS (Medicare/Medicaid), reinsurers"
    ),
    "trust_deficit": True,
    "data_sensitivity": (
        "Applicant health data (GINA, ADA, HIPAA). "
        "Customer financial profile for suitability (Reg BI). "
        "Underwriting class/table ratings — reveals competitive pricing."
    ),
    "gep_value": (
        "Uniquely strong suitability story vs other P&C connectors. "
        "FINRA/Reg BI: prove annuity suitability assessment ran on every sale "
        "without disclosing customer financial profile. "
        "GINA compliance: cross-run consistency proves health conditions not used "
        "discriminatorily without producing protected health information. "
        "SEC variable product: automated vs human decision (GDPR Art. 22 analog)."
    ),
    "proof_ceiling": {
        "suitability_thresholds": "mathematical",
        "underwriting_rules": "mathematical",
        "benefit_determination": "mathematical",
    },
    "cross_run_consistency_applicable": True,
    "buildable": "C# SDK shipped (P10-E)",
    "unique_vs_other_insurance": (
        "Suitability (FINRA/Reg BI) is the unique angle here. "
        "P&C platforms don't have this. L&AH is the only context where "
        "SEC and FINRA are external verifiers alongside state commissioners."
    ),
    "regulatory_hooks": [
        "FINRA Rule 2111 (suitability)",
        "SEC Regulation Best Interest",
        "State insurance market conduct exam",
        "GINA (genetic non-discrimination)",
        "ADA (disability underwriting)",
        "HIPAA (health data)",
        "CMS Medicare/Medicaid program integrity",
    ],
}
*/
