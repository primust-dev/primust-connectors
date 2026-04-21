// Primust Connector: Duck Creek Technologies (DCT) — P&C Insurance Platform
// ==========================================================================
// Fit: STRONG
// Verifier: State insurance commissioners, reinsurers, surplus lines regulators
// Problem solved: Same as Guidewire — prove claims adjudication and rating ran
//                per policy terms without disclosing claimant data or pricing
// Proof ceiling: Mathematical via DCT Extensions framework (in-process C#)
// Buildable: C# SDK (P10-E — shipped)
//
// Duck Creek platform:
//   DCT Policy — policy administration and rating
//   DCT Claims — claims management and adjudication
//   DCT Billing — billing and payment
//   DCT OnDemand — SaaS; DCT On-Prem — self-hosted
//
// DCT Extensions:
//   Duck Creek's native extensibility framework. C# plugins implement
//   IDuckCreekExtension and are registered in the DCT Extension Catalog.
//   Fired via event hooks: BeforeRatingRequest, AfterRatingResponse,
//   BeforePaymentAuthorization, AfterClaimDecision, etc.
//   This is the in-process hook — identical pattern to Guidewire IPlugin.
//
// C# SDK integration:
//   dotnet add package Primust.SDK
//   using Primust;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DuckCreek.Extensions;       // DCT Extensions framework
using DuckCreek.Policy.Rating;    // DCT Policy rating API
using DuckCreek.Claims;           // DCT Claims API
using Primust;                    // Primust C# SDK

namespace Primust.Adapters.DuckCreek
{
    /// <summary>
    /// Primust governance extension for Duck Creek Technologies.
    /// Implements IDuckCreekExtension for both Policy (rating) and Claims.
    ///
    /// Registration in DCT Extension Catalog (extension-catalog.json):
    /// {
    ///   "extensionId": "PrimustGovernance",
    ///   "assembly": "Primust.Adapters.DuckCreek",
    ///   "class": "Primust.Adapters.DuckCreek.PrimustGovernanceExtension",
    ///   "hooks": [
    ///     "Policy.Rating.AfterRatingResponse",
    ///     "Claims.Payment.BeforePaymentAuthorization",
    ///     "Claims.Adjudication.AfterCoverageDecision"
    ///   ]
    /// }
    ///
    /// Configuration (appsettings.json):
    /// {
    ///   "Primust": {
    ///     "ApiKey": "pk_live_...",
    ///     "WorkflowId": "duck-creek-underwriting-v2",
    ///     "RatingManifestId": "sha256:...",
    ///     "ClaimsManifestId": "sha256:...",
    ///     "PaymentManifestId": "sha256:..."
    ///   }
    /// }
    /// </summary>
    public class PrimustGovernanceExtension : IDuckCreekExtension
    {
        private readonly Pipeline _pipeline;
        private readonly string _ratingManifestId;
        private readonly string _claimsManifestId;
        private readonly string _paymentManifestId;

        public PrimustGovernanceExtension(
            Pipeline pipeline,
            string ratingManifestId,
            string claimsManifestId,
            string paymentManifestId)
        {
            _pipeline = pipeline;
            _ratingManifestId = ratingManifestId;
            _claimsManifestId = claimsManifestId;
            _paymentManifestId = paymentManifestId;
        }

        // ------------------------------------------------------------------
        // Rating hook — AfterRatingResponse
        // ------------------------------------------------------------------

        /// <summary>
        /// Called after DCT Policy produces a rating response.
        /// Records proof that rating algorithm ran with specific inputs.
        ///
        /// Proof level: MATHEMATICAL
        /// - Rating is deterministic: same risk profile → same premium
        /// - Arithmetic: base_rate × rating_factors = final_premium
        /// - Cross-run consistency: detects inconsistent rating across book
        ///
        /// State exam use case: commissioner proves all risks rated consistently
        /// without receiving individual policyholder applications.
        ///
        /// Anti-selection protection: rating factors (territory, class codes)
        /// not disclosed to verifier — preventing manipulation of future submissions.
        /// </summary>
        public async Task OnAfterRatingResponseAsync(
            IRatingContext context,
            RatingResponse response)
        {
            var run = _pipeline.Open();

            try
            {
                var checkResult = response.IsSuccessful
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                // Input binding: policy + risk identifiers + rating plan version
                // Rating factors (territory, class, coverage amounts) committed locally
                // Final premium output committed — verifier can verify arithmetic
                var inputBinding = BuildRatingInputBinding(
                    context.PolicyNumber,
                    context.RatingPlanVersion,
                    context.RiskData
                );

                // Output: computed premium — Mathematical proof of arithmetic
                var outputBinding = response.FinalPremium.ToString("F2");

                var recordResult = await run.RecordAsync(new RecordInput
                {
                    Check = "duck_creek_rating",
                    ManifestId = _ratingManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(inputBinding),
                    Output = System.Text.Encoding.UTF8.GetBytes(outputBinding),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["policy_number"] = context.PolicyNumber,
                        ["rating_plan_version"] = context.RatingPlanVersion,
                        ["coverage_count"] = response.Coverages?.Count ?? 0,
                        // premium NOT included — reveals pricing
                        // rating factors NOT included — enables anti-selection
                    },
                    Visibility = "opaque"
                });

                // Store commitment hash on context for log linkage
                context.SetExtensionData("PrimustCommitmentHash", recordResult.CommitmentHash);

                var vpec = await run.CloseAsync();
                context.SetExtensionData("PrimustVPEC", vpec.VpecId);
            }
            catch (Exception ex)
            {
                // SDK degrades gracefully — governance gap recorded, rating not blocked
                run.RecordSystemError(ex.Message);
                await run.CloseAsync();
            }
        }

        // ------------------------------------------------------------------
        // Claims payment authorization hook
        // ------------------------------------------------------------------

        /// <summary>
        /// Called before DCT Claims authorizes a payment.
        /// Records proof that payment authorization rules ran.
        ///
        /// Proof level: MATHEMATICAL
        /// Three arithmetic checks identical to Guidewire:
        ///   payment ≤ adjuster authority limit
        ///   cumulative payments ≤ policy limit
        ///   reserve ≥ payment amount
        ///
        /// Reinsurance use case: cedant proves payments on ceded claims
        /// were authorized per policy terms without sharing claim files.
        /// </summary>
        public async Task OnBeforePaymentAuthorizationAsync(
            IPaymentContext context,
            PaymentAuthorizationRequest request)
        {
            var run = _pipeline.Open();

            try
            {
                bool authorityOk = request.Amount <= context.AdjusterAuthorityLimit;
                bool limitOk = (context.CumulativePaid + request.Amount) <= context.PolicyLimit;
                bool reserveOk = context.TotalReserves >= request.Amount;

                var checkResult = (authorityOk && limitOk && reserveOk)
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                // All three values in the input — Mathematical proof
                // Verifier can replay: amount ≤ authority, cumulative ≤ limit, reserve ≥ amount
                var inputBinding = string.Format(
                    "claim:{0}|payment:{1:F2}|authority:{2:F2}|limit:{3:F2}|reserve:{4:F2}",
                    context.ClaimNumber,
                    request.Amount,
                    context.AdjusterAuthorityLimit,
                    context.PolicyLimit,
                    context.TotalReserves
                );

                await run.RecordAsync(new RecordInput
                {
                    Check = "duck_creek_payment_authorization",
                    ManifestId = _paymentManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(inputBinding),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["claim_number"] = context.ClaimNumber,
                        ["authority_check"] = authorityOk,
                        ["limit_check"] = limitOk,
                        ["reserve_check"] = reserveOk,
                        // amounts NOT included — financial data
                    },
                    Visibility = "opaque"
                });

                await run.CloseAsync();

                // Block payment if checks fail
                if (!checkResult.Equals(CheckResult.Pass))
                {
                    request.Deny("Payment authorization checks failed — see governance record");
                }
            }
            catch (Exception ex)
            {
                run.RecordSystemError(ex.Message);
                await run.CloseAsync();
                // Do NOT block payment on governance system failure — degrade gracefully
            }
        }

        // ------------------------------------------------------------------
        // Coverage decision hook — AfterCoverageDecision
        // ------------------------------------------------------------------

        /// <summary>
        /// Called after DCT Claims makes a coverage determination.
        /// Records proof that coverage rules were applied.
        ///
        /// Same reinsurance story as Guidewire:
        /// Cedant proves coverage determination ran per policy terms
        /// without sending the reinsurer the full claim file.
        /// </summary>
        public async Task OnAfterCoverageDecisionAsync(
            IClaimContext context,
            CoverageDecision decision)
        {
            var run = _pipeline.Open();

            try
            {
                var checkResult = decision.IsCovered
                    ? CheckResult.Pass
                    : CheckResult.Fail;

                await run.RecordAsync(new RecordInput
                {
                    Check = "duck_creek_coverage_decision",
                    ManifestId = _claimsManifestId,
                    Input = System.Text.Encoding.UTF8.GetBytes(
                        $"claim:{context.ClaimNumber}|coverage:{decision.CoverageCode}|policy:{context.PolicyVersion}"
                    ),
                    CheckResult = checkResult,
                    Details = new Dictionary<string, object>
                    {
                        ["claim_number"] = context.ClaimNumber,
                        ["coverage_code"] = decision.CoverageCode,
                        ["is_covered"] = decision.IsCovered,
                        ["determination"] = decision.Determination,
                        // loss details NOT included — claimant data
                    },
                    Visibility = "opaque"
                });

                var vpec = await run.CloseAsync();
                // Attach VPEC ID to claim record for reinsurance package
                context.SetExtensionData("PrimustVPEC", vpec.VpecId);
            }
            catch (Exception)
            {
                await run.CloseAsync();
            }
        }

        // ------------------------------------------------------------------
        // Internal helpers
        // ------------------------------------------------------------------

        private string BuildRatingInputBinding(
            string policyNumber,
            string ratingPlanVersion,
            IDictionary<string, object> riskData)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append($"policy:{policyNumber}|plan:{ratingPlanVersion}");
            foreach (var kv in new SortedDictionary<string, object>(riskData))
            {
                sb.Append($"|{kv.Key}:{kv.Value}");
            }
            return sb.ToString();
        }
    }
}

/*
FIT_VALIDATION = {
    "platform": "Duck Creek Technologies",
    "category": "P&C Insurance Platform",
    "fit": "STRONG",
    "external_verifier": "State insurance commissioners, reinsurers, surplus lines regulators",
    "trust_deficit": True,
    "data_sensitivity": (
        "Policyholder data (PII). Rating factors — revealing enables anti-selection. "
        "Claimant medical records / loss details — protected. Reserve amounts."
    ),
    "gep_value": (
        "Same as Guidewire — different platform, same story. "
        "Rating: proves consistent rating across book without sharing applications. "
        "Claims: proves adjudication ran per policy terms without sharing claim files. "
        "Reinsurance: math replaces disclosure for treaty compliance."
    ),
    "proof_ceiling": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable": "C# SDK shipped (P10-E)",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC model rating law",
        "Lloyd's market conduct standards",
        "Reinsurance treaty compliance audit",
    ],
}
*/
