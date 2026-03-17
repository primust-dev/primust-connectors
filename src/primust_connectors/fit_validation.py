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
Primust Connector Fit Validation
=================================
Validates fit for all connectors against the three-property filter:
  1. Regulated process
  2. External verifier with trust deficit
  3. Data that can't be disclosed to satisfy that verifier

Run: python -m primust_connectors.fit_validation
"""
from __future__ import annotations

from primust_connectors.comply_advantage import FIT_VALIDATION as COMPLY_FIT
from primust_connectors.wolters_kluwer import FIT_VALIDATION as UTD_FIT
from primust_connectors.credit_brms import BLAZE_FIT_VALIDATION, ODM_FIT_VALIDATION
from primust_connectors.nice_actimize import FIT_VALIDATION as ACTIMIZE_FIT
from primust_connectors.fico_falcon import FIT_VALIDATION as FALCON_FIT
from primust_connectors.pega_decisioning import FIT_VALIDATION as PEGA_FIT

GUIDEWIRE_FIT = {
    "platform": "Guidewire ClaimCenter / PolicyCenter",
    "category": "Insurance Claims Adjudication",
    "fit": "STRONG (reinsurance context specifically)",
    "external_verifier": "Reinsurers, Lloyd's syndicates, state DOI examiners",
    "trust_deficit": True,
    "data_sensitivity": (
        "Claimant medical records (HIPAA), loss details, financial reserves — "
        "protected from counterparty disclosure in reinsurance context"
    ),
    "gep_value": (
        "Cedant proves adjudication ran per policy terms on each claim without "
        "providing the reinsurer the claim file. Math replaces disclosure."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "Java (P10-D) + Guidewire Studio license",
    "design_partner_required": True,
    "regulatory_hooks": [
        "State insurance market conduct exam requirements",
        "Lloyd's market conduct standards",
        "HIPAA for health-related claims",
        "NAIC model audit rule",
    ],
}

# -- Java spec file FIT_VALIDATION dicts (from comment blocks) --

HEALTHSHARE_FIT = {
    "platform": "InterSystems HealthShare / IRIS for Health",
    "category": "Clinical Governance / HIE",
    "fit": "STRONG",
    "external_verifier": "CMS, Joint Commission, state health departments, HIE participants",
    "trust_deficit": True,
    "data_sensitivity": "Patient clinical data — HIPAA PHI, sensitive categories (mental health, substance)",
    "gep_value": (
        "Proves clinical governance processes ran on patient data. "
        "CMS auditor, Joint Commission surveyor, HIE participant confirms "
        "processes ran without receiving PHI. HIPAA paradox resolved. "
        "Consent verification chain provides portable proof for HIE disputes."
    ),
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": "mathematical",
    "proof_ceiling_notes": (
        "Consent check = set_membership (deterministic). "
        "Consent expiry = threshold_comparison (arithmetic). "
        "Both Mathematical in-process via IRIS Java Binding. "
        "CDS rule evaluation itself is Attestation (rule logic proprietary). "
        "Per-stage breakdown surfaces Mathematical consent + expiry stages."
    ),
    "buildable_today": False,
    "sdk_required": "Java SDK (P10-D) + IRIS Java Gateway config",
    "cross_run_consistency_applicable": True,
    "regulatory_hooks": [
        "HIPAA 45 CFR §164.312 (technical safeguards)",
        "CMS Conditions of Participation §482.24",
        "HL7 SMART on FHIR consent management",
        "TEFCA data sharing framework",
        "Joint Commission NPSG",
    ],
}

SAPIENS_DECISION_FIT = {
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
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_java_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "Java SDK (P10-D)",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC unfair trade practices model act",
        "Lloyd's market conduct standards",
        "Reinsurance treaty compliance",
        "GDPR (EU life insurance underwriting)",
    ],
}

# -- C# spec file FIT_VALIDATION dicts (from comment blocks) --

DUCK_CREEK_FIT = {
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
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_csharp_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "C# SDK (P10-E)",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC model rating law",
        "Lloyd's market conduct standards",
        "Reinsurance treaty compliance audit",
    ],
}

MAJESCO_FIT = {
    "platform": "Majesco CloudInsurer",
    "category": "P&C / L&AH Insurance Platform",
    "fit": "STRONG",
    "external_verifier": "State insurance commissioners, reinsurers",
    "trust_deficit": True,
    "data_sensitivity": "Policyholder PII, health data (L&AH), rating factors, claimant records",
    "gep_value": "Identical to Duck Creek and Guidewire — same story, different platform.",
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_csharp_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "C# SDK (P10-E)",
    "note": "L&AH line has additional state non-discrimination compliance angle — health data is sensitive.",
    "regulatory_hooks": [
        "State insurance market conduct exam",
        "NAIC model underwriting guidelines",
        "ADA/GINA compliance for L&AH",
        "Reinsurance treaty compliance",
    ],
}

SAPIENS_ALIS_FIT = {
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
    "proof_ceiling_today": "attestation",
    "proof_ceiling_post_csharp_sdk": "mathematical",
    "cross_run_consistency_applicable": True,
    "buildable_today": False,
    "sdk_required": "C# SDK (P10-E)",
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

ALL_CONNECTORS = [
    # Python connectors (importable, buildable today)
    COMPLY_FIT,
    ACTIMIZE_FIT,
    BLAZE_FIT_VALIDATION,
    ODM_FIT_VALIDATION,
    UTD_FIT,
    FALCON_FIT,       # PARTIAL fit — honest assessment
    PEGA_FIT,         # PARTIAL fit — context dependent
    # Java spec files (require Java SDK)
    GUIDEWIRE_FIT,
    HEALTHSHARE_FIT,
    SAPIENS_DECISION_FIT,
    # C# spec files (require C# SDK P10-E)
    DUCK_CREEK_FIT,
    MAJESCO_FIT,
    SAPIENS_ALIS_FIT,
]


def validate_fit(connector: dict) -> dict:
    """
    Run the three-property test.
    All three required for strong fit.
    Note: passing 3/3 means the platform HAS all three properties.
    The fit_declared field preserves the honest fit characterization
    (STRONG, PARTIAL, etc.) — a 3/3 score with PARTIAL fit means
    the properties exist but the governance value is limited.
    """
    prop1_regulated = bool(connector.get("regulatory_hooks"))
    prop2_external_verifier = bool(connector.get("external_verifier")) and connector.get("trust_deficit", False)
    prop3_data_sensitivity = bool(connector.get("data_sensitivity"))

    score = sum([prop1_regulated, prop2_external_verifier, prop3_data_sensitivity])
    fit_confirmed = score == 3

    return {
        "platform": connector["platform"],
        "fit_declared": connector["fit"],
        "fit_confirmed": fit_confirmed,
        "score": f"{score}/3",
        "prop1_regulated_process": prop1_regulated,
        "prop2_external_verifier_trust_deficit": prop2_external_verifier,
        "prop3_data_cannot_be_disclosed": prop3_data_sensitivity,
        "proof_ceiling_today": connector.get("proof_ceiling_today") or connector.get("proof_ceiling") or "attestation",
        "proof_ceiling_max": connector.get("proof_ceiling_post_java_sdk") or connector.get("proof_ceiling_post_csharp_sdk") or connector.get("proof_ceiling_today") or connector.get("proof_ceiling") or "attestation",
        "buildable_today": connector.get("buildable_today", False),
        "sdk_blocker": connector.get("sdk_required_for_mathematical") or connector.get("sdk_required"),
        "cross_run_consistency": connector.get("cross_run_consistency_applicable", False),
    }


def print_summary() -> None:
    print("\n" + "=" * 92)
    print("PRIMUST CONNECTOR FIT VALIDATION")
    print("=" * 92)
    print(f"{'Platform':<32} {'Fit':>8} {'Score':>6} {'Ready':>6} {'Ceiling (today)':>16} {'Max (SDK)':>16}")
    print("-" * 92)

    for connector in ALL_CONNECTORS:
        result = validate_fit(connector)
        today_str = "Y" if result["buildable_today"] else "N"
        ceiling_today = result["proof_ceiling_today"]
        ceiling_max = result["proof_ceiling_max"]
        if isinstance(ceiling_today, dict):
            ceiling_today = "mixed"
        if isinstance(ceiling_max, dict):
            ceiling_max = "mathematical"
        fit_decl = str(result["fit_declared"]).split(" ")[0]  # just STRONG or PARTIAL
        max_str = ceiling_max if ceiling_max != ceiling_today else "—"
        print(
            f"{result['platform'][:32]:<32} "
            f"{fit_decl:>8} "
            f"{result['score']:>6} "
            f"{today_str:>6} "
            f"{str(ceiling_today):>16} "
            f"{max_str:>16}"
        )

    print()


if __name__ == "__main__":
    print_summary()
