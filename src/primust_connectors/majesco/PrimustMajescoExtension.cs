// Primust Connector: Majesco CloudInsurer
// ========================================
// Fit: STRONG (same use cases as Duck Creek and Guidewire)
// Verifier: State insurance commissioners, reinsurers
// Proof ceiling: Mathematical (C# in-process, Majesco extension framework)
// Buildable: C# SDK (P10-E — shipped)
//
// Majesco platform:
//   Majesco CloudInsurer P&C — property and casualty
//   Majesco CloudInsurer L&AH — life, annuity, health
//   Majesco Digital1st — digital insurance platform
//
// Integration surface:
//   Majesco uses a .NET extension/plugin architecture similar to DCT.
//   Business Rules Engine (BRE) exposes IMajescoRuleHandler interface.
//   CloudInsurer REST API available for cloud deployments (Attestation ceiling).
//   On-premise / private cloud: in-process via IMajescoRuleHandler (Mathematical).
//
// Note on Majesco vs Duck Creek vs Guidewire:
//   All three are P&C insurance platforms with identical governance stories.
//   The connector code structure is nearly identical — different class names,
//   same proof architecture. When selling to an insurer, ask which platform
//   they run and point to the correct connector. Don't oversell differences.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Majesco.CloudInsurer.Extensions;    // Majesco extension framework
using Majesco.CloudInsurer.Policy;        // Policy/Rating API
using Majesco.CloudInsurer.Claims;        // Claims API
using Primust;

namespace Primust.Adapters.Majesco
{
    /// <summary>
    /// Primust governance extension for Majesco CloudInsurer.
    /// Implements IMajescoExtension for Policy and Claims modules.
    ///
    /// Registration in Majesco Extension Registry:
    /// {
    ///   "ExtensionId": "PrimustGovernance",
    ///   "Assembly": "Primust.Adapters.Majesco",
    ///   "Class": "Primust.Adapters.Majesco.PrimustMajescoExtension",
    ///   "Events": [
    ///     "Policy.Rating.Completed",
    ///     "Claims.Coverage.Determined",
    ///     "Claims.Payment.Authorizing"
    ///   ]
    /// }
    /// </summary>
    public class PrimustMajescoExtension : IMajescoExtension
    {
        private readonly Pipeline _pipeline;
        private readonly string _ratingManifestId;
        private readonly string _coverageManifestId;
        private readonly string _paymentManifestId;

        public PrimustMajescoExtension(
            Pipeline pipeline,
            string ratingManifestId,
            string coverageManifestId,
            string paymentManifestId)
        {
            _pipeline = pipeline;
            _ratingManifestId = ratingManifestId;
            _coverageManifestId = coverageManifestId;
            _paymentManifestId = paymentManifestId;
        }

        // ------------------------------------------------------------------
        // Policy rating completion event
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired when Majesco BRE completes a rating calculation.
        ///
        /// Proof level: MATHEMATICAL
        /// Rating is deterministic arithmetic — base_rate × factors = premium.
        /// Same risk profile must always produce same premium (cross-run consistency).
        ///
        /// L&AH use case (stronger fit than P&C in some states):
        /// Life insurance underwriting decisions must comply with state
        /// non-discrimination laws. Proving consistent rate application to
        /// insurance department without disclosing individual health data.
        /// </summary>
        public async Task OnPolicyRatingCompletedAsync(
            IMajescoPolicyContext context,
            RatingCompletedEvent ratingEvent)
        {
            var run = _pipeline.Open();

            try
            {
                var checkResult = ratingEvent.IsSuccessful
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                // Deterministic input binding
                var inputBinding = BuildSortedBinding(new Dictionary<string, string>
                {
                    ["policy"] = context.PolicyNumber,
                    ["product"] = context.ProductCode,
                    ["plan_version"] = ratingEvent.RatingPlanVersion,
                    ["effective_date"] = context.EffectiveDate.ToString("yyyy-MM-dd"),
                    // risk factors appended below
                });

                foreach (var factor in GetSortedRatingFactors(context))
                {
                    inputBinding += $"|{factor.Key}:{factor.Value}";
                }

                await run.RecordAsync(new RecordInput
                {
                    Check = "majesco_policy_rating",
                    ManifestId = _ratingManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(inputBinding),
                    Output = System.Text.Encoding.UTF8.GetBytes(
                        ratingEvent.FinalPremium.ToString("F2")
                    ),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["policy_number"] = context.PolicyNumber,
                        ["product_code"] = context.ProductCode,
                        ["rating_plan_version"] = ratingEvent.RatingPlanVersion,
                    },
                    Visibility = "opaque"
                });

                var vpec = await run.CloseAsync();
                context.SetMetadata("PrimustVPEC", vpec.VpecId);
                context.SetMetadata("PrimustCommitment", run.LastCommitmentHash);
            }
            catch (Exception)
            {
                await run.CloseAsync();
            }
        }

        // ------------------------------------------------------------------
        // Claims coverage determination event
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired when Majesco Claims determines coverage on a new claim.
        /// Records proof for reinsurance treaty compliance and regulatory exams.
        /// </summary>
        public async Task OnCoverageDeterminedAsync(
            IMajescoClaimContext context,
            CoverageDeterminedEvent coverageEvent)
        {
            var run = _pipeline.Open();

            try
            {
                await run.RecordAsync(new RecordInput
                {
                    Check = "majesco_coverage_determination",
                    ManifestId = _coverageManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(
                        $"claim:{context.ClaimNumber}|coverage:{coverageEvent.CoverageCode}|policy:{context.PolicyVersion}"
                    ),
                    CheckResult = coverageEvent.IsCovered ? CheckResult.Pass : CheckResult.Fail,
                    Details = new Dictionary<string, object>
                    {
                        ["claim_number"] = context.ClaimNumber,
                        ["coverage_code"] = coverageEvent.CoverageCode,
                        ["is_covered"] = coverageEvent.IsCovered,
                    },
                    Visibility = "opaque"
                });

                var vpec = await run.CloseAsync();
                context.SetMetadata("PrimustVPEC", vpec.VpecId);
            }
            catch (Exception)
            {
                await run.CloseAsync();
            }
        }

        // ------------------------------------------------------------------
        // Payment authorization event
        // ------------------------------------------------------------------

        /// <summary>
        /// Fired before Majesco Claims authorizes a payment.
        /// Identical arithmetic checks to Duck Creek and Guidewire.
        /// Mathematical proof: payment ≤ authority, cumulative ≤ limit, reserve ≥ payment.
        /// </summary>
        public async Task OnPaymentAuthorizingAsync(
            IMajescoClaimContext context,
            PaymentAuthorizationEvent paymentEvent)
        {
            var run = _pipeline.Open();

            try
            {
                bool authorityOk = paymentEvent.Amount <= context.AdjusterAuthorityLimit;
                bool limitOk = (context.TotalPaid + paymentEvent.Amount) <= context.PolicyLimit;
                bool reserveOk = context.TotalReserves >= paymentEvent.Amount;

                var checkResult = (authorityOk && limitOk && reserveOk)
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                await run.RecordAsync(new RecordInput
                {
                    Check = "majesco_payment_authorization",
                    ManifestId = _paymentManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(
                        $"claim:{context.ClaimNumber}|amount:{paymentEvent.Amount:F2}" +
                        $"|authority:{context.AdjusterAuthorityLimit:F2}" +
                        $"|limit:{context.PolicyLimit:F2}|reserve:{context.TotalReserves:F2}"
                    ),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["claim_number"] = context.ClaimNumber,
                        ["authority_ok"] = authorityOk,
                        ["limit_ok"] = limitOk,
                        ["reserve_ok"] = reserveOk,
                    },
                    Visibility = "opaque"
                });

                await run.CloseAsync();

                if (!checkResult.Equals(CheckResult.Pass))
                    paymentEvent.Deny("Authorization checks failed");
            }
            catch (Exception)
            {
                await run.CloseAsync();
            }
        }

        // ------------------------------------------------------------------
        // Internal helpers
        // ------------------------------------------------------------------

        private string BuildSortedBinding(Dictionary<string, string> fields)
        {
            var sorted = new SortedDictionary<string, string>(fields);
            return string.Join("|", System.Linq.Enumerable.Select(sorted, kv => $"{kv.Key}:{kv.Value}"));
        }

        private SortedDictionary<string, object> GetSortedRatingFactors(IMajescoPolicyContext context)
        {
            var factors = new SortedDictionary<string, object>();
            foreach (var factor in context.RatingFactors)
                factors[factor.FactorCode] = factor.Value;
            return factors;
        }
    }
}

/*
FIT_VALIDATION = {
    "platform": "Majesco CloudInsurer",
    "category": "P&C / L&AH Insurance Platform",
    "fit": "STRONG",
    "external_verifier": "State insurance commissioners, reinsurers",
    "trust_deficit": True,
    "data_sensitivity": "Policyholder PII, health data (L&AH), rating factors, claimant records",
    "gep_value": "Identical to Duck Creek and Guidewire — same story, different platform.",
    "proof_ceiling": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable": "C# SDK shipped (P10-E)",
    "note": "L&AH line has additional state non-discrimination compliance angle — health data is sensitive.",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC model underwriting guidelines",
        "ADA/GINA compliance for L&AH",
        "Reinsurance treaty compliance",
    ],
}
*/
