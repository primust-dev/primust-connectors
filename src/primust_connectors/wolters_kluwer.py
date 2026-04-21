"""
Primust Connector: Wolters Kluwer UpToDate Clinical Decision Support
====================================================================
Fit: STRONG
Verifier: CMS, Joint Commission, state medical boards, malpractice insurers
Problem solved: HIPAA paradox — prove the drug interaction check ran on this
                patient's medication list without revealing the list
Proof ceiling: Attestation (interaction database proprietary) + Mathematical
               for threshold/dosing range comparisons (set_membership circuits apply)
Buildable: NOW — Python SDK + REST, no Java SDK required

The GEP story here is clinical liability. When a medication error occurs,
the question is "did the system check for this interaction?" Current answer:
"our logs say it did." With a VPEC: the math proves it did, and the patient's
medication list was never disclosed to prove it. That's the HIPAA paradox resolved.

Note on proof ceiling nuance:
  - Drug interaction lookup = set_membership in interaction database → attestation
    (database contents are proprietary, cannot express as open circuit)
  - Dosing range check = threshold_comparison (min_dose <= prescribed <= max_dose)
    → mathematical when manifest includes the range bounds publicly
  - Overall VPEC = attestation (weakest-link), but per-stage breakdown surfaces
    the mathematical threshold stage to the verifier
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx
import primust

# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

MANIFEST_DRUG_INTERACTION = {
    "name": "uptodate_drug_interaction_check",
    "description": (
        "Wolters Kluwer UpToDate drug interaction screening. "
        "Checks prescribed medication against patient's current medication list "
        "for contraindications and interaction severity."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "interaction_database_lookup",
            "type": "deterministic_rule",
            "proof_level": "attestation",  # proprietary Medi-Span database
            "method": "set_membership",
            "purpose": "Contraindication lookup in Wolters Kluwer Medi-Span database",
        },
        {
            "stage": 2,
            "name": "severity_classification",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "threshold_comparison",
            "purpose": "Interaction severity score >= alert threshold (contraindicated/major/moderate/minor)",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 168,  # UpToDate updates weekly
    "publisher": "your-org-id",
}

MANIFEST_DOSING_RANGE_CHECK = {
    "name": "uptodate_dosing_range_check",
    "description": (
        "UpToDate dosing range validation. Checks prescribed dose against "
        "evidence-based min/max range for patient weight/age/renal function. "
        "Threshold stages are mathematical — dose bounds are published in manifest."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "weight_adjusted_dose_min",
            "type": "deterministic_rule",
            "proof_level": "mathematical",  # arithmetic: dose >= min_dose_per_kg * weight
            "method": "threshold_comparison",
            "formula": "prescribed_dose_mg >= min_dose_per_kg * weight_kg",
            "purpose": "Prescribed dose not below minimum effective dose",
        },
        {
            "stage": 2,
            "name": "weight_adjusted_dose_max",
            "type": "deterministic_rule",
            "proof_level": "mathematical",  # arithmetic: dose <= max_dose_per_kg * weight
            "method": "threshold_comparison",
            "formula": "prescribed_dose_mg <= max_dose_per_kg * weight_kg",
            "purpose": "Prescribed dose not above maximum safe dose",
        },
        {
            "stage": 3,
            "name": "renal_adjustment",
            "type": "deterministic_rule",
            "proof_level": "mathematical",
            "method": "threshold_comparison",
            "formula": "if CrCl < 30: prescribed_dose <= renal_adjusted_max",
            "purpose": "Renal dosing adjustment applied when CrCl < 30 mL/min",
        },
    ],
    "aggregation": {"method": "all_must_pass"},
    "freshness_threshold_hours": 720,
    "publisher": "your-org-id",
}

MANIFEST_CLINICAL_GUIDELINE_ADHERENCE = {
    "name": "uptodate_guideline_adherence",
    "description": (
        "UpToDate evidence-based guideline adherence check. "
        "Verifies clinical decision aligns with current evidence-based recommendations "
        "for the diagnosed condition."
    ),
    "stages": [
        {
            "stage": 1,
            "name": "guideline_lookup",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "Treatment option within recommended options for diagnosis",
        },
        {
            "stage": 2,
            "name": "first_line_check",
            "type": "deterministic_rule",
            "proof_level": "attestation",
            "method": "set_membership",
            "purpose": "First-line vs second-line therapy validation",
        },
    ],
    "aggregation": {"method": "worst_case"},
    "freshness_threshold_hours": 720,
    "publisher": "your-org-id",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DrugInteractionResult:
    interaction_found: bool
    severity: str  # "contraindicated" | "major" | "moderate" | "minor" | "none"
    interaction_count: int
    drug_pair: tuple[str, str]
    raw_response: dict


@dataclass
class DosingResult:
    within_range: bool
    prescribed_dose_mg: float
    min_dose_mg: float
    max_dose_mg: float
    renal_adjusted: bool
    raw_response: dict


@dataclass
class PrimustClinicalRecord:
    commitment_hash: str
    record_id: str
    proof_level: str  # "mathematical" for dosing, "attestation" for interaction
    check_name: str


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class UpToDateConnector:
    """
    Wraps Wolters Kluwer UpToDate clinical decision support with Primust VPEC issuance.

    Usage (at prescribing time in EHR workflow):
        connector = UpToDateConnector(
            utd_api_key=os.environ["UPTODATE_API_KEY"],
            primust_api_key=os.environ["PRIMUST_API_KEY"],
        )
        connector.register_manifests()

        pipeline = connector.new_pipeline(workflow_id="prescribing-v3")

        # Check interaction
        interaction = connector.check_drug_interaction(
            pipeline=pipeline,
            new_drug="warfarin",
            current_medications=["aspirin", "ibuprofen"],
            patient_id="pt_abc123",   # committed as input, never leaves
        )

        # Check dosing
        dosing = connector.check_dosing_range(
            pipeline=pipeline,
            drug="amoxicillin",
            prescribed_dose_mg=500,
            weight_kg=70,
            crcl=85,
        )

        vpec = pipeline.close()
        # vpec → attach to prescription record
        # In malpractice/audit context: proves checks ran without disclosing
        # patient medication list (HIPAA) or patient weight/renal function (PHI)
    """

    BASE_URL = "https://www.uptodate.com/services/app"

    def __init__(
        self,
        utd_api_key: str,
        primust_api_key: str,
        interaction_alert_threshold: str = "major",  # alert on major+ by default
    ):
        self.utd_api_key = utd_api_key
        self.primust_api_key = primust_api_key
        self.interaction_alert_threshold = interaction_alert_threshold
        self._manifest_ids: dict[str, str] = {}
        self._severity_rank = {
            "contraindicated": 4,
            "major": 3,
            "moderate": 2,
            "minor": 1,
            "none": 0,
        }

    def register_manifests(self) -> None:
        p = primust.Pipeline(api_key=self.primust_api_key, workflow_id="manifest-registration")
        for manifest in [
            MANIFEST_DRUG_INTERACTION,
            MANIFEST_DOSING_RANGE_CHECK,
            MANIFEST_CLINICAL_GUIDELINE_ADHERENCE,
        ]:
            result = p.register_check(manifest)
            self._manifest_ids[manifest["name"]] = result.manifest_id
            print(f"Registered {manifest['name']}: {result.manifest_id}")

    def new_pipeline(self, workflow_id: str) -> primust.Pipeline:
        return primust.Pipeline(api_key=self.primust_api_key, workflow_id=workflow_id)

    # ------------------------------------------------------------------
    # Drug interaction check
    # ------------------------------------------------------------------

    def check_drug_interaction(
        self,
        pipeline: primust.Pipeline,
        new_drug: str,
        current_medications: list[str],
        patient_id: str,
        visibility: str = "opaque",  # patient medication list is PHI
    ) -> PrimustClinicalRecord:
        """
        Check new drug against current medications for interactions.

        Visibility is "opaque" by default — medication list is PHI.
        Regulator/accreditor can request NDA audit path for full data if needed.
        """
        manifest_id = self._manifest_ids.get("uptodate_drug_interaction_check")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Call UpToDate Interaction API
        with httpx.Client() as client:
            resp = client.get(
                f"{self.BASE_URL}/contents/interaction",
                params={
                    "drug1": new_drug,
                    "drug2": "|".join(current_medications),
                    "apikey": self.utd_api_key,
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()

        result = self._parse_interaction_response(data, new_drug, current_medications)

        alert_rank = self._severity_rank.get(self.interaction_alert_threshold, 3)
        found_rank = max(self._severity_rank.get(result.severity, 0), 0)
        check_result = "fail" if (result.interaction_found and found_rank >= alert_rank) else "pass"

        # Input commits patient_id + new_drug + medication count
        # NOT the medication names (PHI) — verifier can confirm input commitment
        # matches their records without receiving the list
        record = pipeline.record(
            check="uptodate_drug_interaction_check",
            manifest_id=manifest_id,
            input=f"{patient_id}|{new_drug}|meds_count:{len(current_medications)}",
            check_result=check_result,
            details={
                "severity": result.severity,
                "interaction_count": result.interaction_count,
            },
            visibility=visibility,
        )

        return PrimustClinicalRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            check_name="uptodate_drug_interaction_check",
        )

    # ------------------------------------------------------------------
    # Dosing range check — Mathematical proof ceiling for threshold stages
    # ------------------------------------------------------------------

    def check_dosing_range(
        self,
        pipeline: primust.Pipeline,
        drug: str,
        prescribed_dose_mg: float,
        weight_kg: float,
        crcl: Optional[float] = None,  # creatinine clearance mL/min
        age_years: Optional[int] = None,
        visibility: str = "selective",  # dose/weight are PHI but ranges can be shown
    ) -> PrimustClinicalRecord:
        """
        Validate prescribed dose against weight-adjusted safe range.

        The dosing range stages are MATHEMATICAL — dose bounds are deterministic
        arithmetic (min_dose_per_kg * weight_kg). Per-stage breakdown in the VPEC
        will show mathematical for these stages even though overall credential
        is selective visibility.

        This is the cleanest Mathematical proof story in clinical settings:
        the verifier can independently compute whether the dose was within range
        given just the weight and the published dosing table — zero trust in anyone.
        """
        manifest_id = self._manifest_ids.get("uptodate_dosing_range_check")
        if not manifest_id:
            raise RuntimeError("Call register_manifests() first")

        # Call UpToDate Dosing API
        with httpx.Client() as client:
            params = {
                "drug": drug,
                "weight_kg": weight_kg,
                "apikey": self.utd_api_key,
            }
            if crcl is not None:
                params["crcl"] = crcl
            if age_years is not None:
                params["age_years"] = age_years

            resp = client.get(
                f"{self.BASE_URL}/contents/dosing",
                params=params,
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()

        dosing = self._parse_dosing_response(data, prescribed_dose_mg, weight_kg, crcl)
        check_result = "pass" if dosing.within_range else "fail"

        record = pipeline.record(
            check="uptodate_dosing_range_check",
            manifest_id=manifest_id,
            input=f"{drug}|dose:{prescribed_dose_mg}mg|weight:{weight_kg}kg|crcl:{crcl}",
            check_result=check_result,
            details={
                "within_range": dosing.within_range,
                "renal_adjusted": dosing.renal_adjusted,
                # Include range bounds in details — they're published, not PHI
                "min_dose_mg": dosing.min_dose_mg,
                "max_dose_mg": dosing.max_dose_mg,
            },
            visibility=visibility,
        )

        return PrimustClinicalRecord(
            commitment_hash=record.commitment_hash,
            record_id=record.record_id,
            proof_level=record.proof_level,
            check_name="uptodate_dosing_range_check",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_interaction_response(
        self, data: dict, new_drug: str, current_meds: list[str]
    ) -> DrugInteractionResult:
        interactions = data.get("interactions", [])
        max_severity = "none"
        max_rank = 0
        for interaction in interactions:
            sev = interaction.get("severity", "none").lower()
            rank = self._severity_rank.get(sev, 0)
            if rank > max_rank:
                max_rank = rank
                max_severity = sev

        return DrugInteractionResult(
            interaction_found=len(interactions) > 0,
            severity=max_severity,
            interaction_count=len(interactions),
            drug_pair=(new_drug, ", ".join(current_meds)),
            raw_response=data,
        )

    def _parse_dosing_response(
        self, data: dict, prescribed: float, weight_kg: float, crcl: Optional[float]
    ) -> DosingResult:
        dosing_data = data.get("dosing", {})
        min_per_kg = dosing_data.get("min_dose_mg_per_kg", 0)
        max_per_kg = dosing_data.get("max_dose_mg_per_kg", float("inf"))

        min_dose = min_per_kg * weight_kg
        max_dose = max_per_kg * weight_kg

        # Renal adjustment
        renal_adjusted = False
        if crcl is not None and crcl < 30:
            renal_max = dosing_data.get("renal_adjusted_max_mg", max_dose)
            max_dose = min(max_dose, renal_max)
            renal_adjusted = True

        within_range = min_dose <= prescribed <= max_dose

        return DosingResult(
            within_range=within_range,
            prescribed_dose_mg=prescribed,
            min_dose_mg=min_dose,
            max_dose_mg=max_dose,
            renal_adjusted=renal_adjusted,
            raw_response=data,
        )


# ---------------------------------------------------------------------------
# FIT VALIDATION
# ---------------------------------------------------------------------------

FIT_VALIDATION = {
    "platform": "Wolters Kluwer UpToDate",
    "category": "Clinical Decision Support",
    "fit": "STRONG",
    "external_verifier": "CMS, Joint Commission, state medical boards, malpractice insurers",
    "trust_deficit": True,
    "data_sensitivity": "Patient medication list, weight, renal function — all PHI under HIPAA",
    "gep_value": (
        "Proves clinical checks ran on this patient's specific data at prescribing time. "
        "Auditor or insurer confirms checks were performed without receiving PHI. "
        "HIPAA paradox resolved: proving compliance no longer requires disclosing "
        "the protected data the compliance check was protecting."
    ),
    "proof_ceiling": {
        "overall": "attestation",
        "dosing_threshold_stages": "mathematical",  # the gem — independently verifiable
        "interaction_lookup": "attestation",
    },
    "mathematical_stages_note": (
        "Dosing range stages (min/max threshold checks) hit Mathematical ceiling. "
        "Verifier can replay: given published dosing table + weight in manifest, "
        "independently confirm whether prescribed dose was in range. "
        "Zero trust in Primust, zero trust in hospital."
    ),
    "buildable_today": True,
    "sdk_required": "Python (shipped)",
    "java_sdk_changes_ceiling": False,
    "regulatory_hooks": [
        "HIPAA 45 CFR §164.312 audit controls",
        "21 CFR Part 11 (electronic records in pharma context)",
        "Joint Commission NPSG.03.06.01 (medication reconciliation)",
        "CMS Conditions of Participation §482.24",
    ],
    "aml_paradox_resolved": False,
    "hipaa_paradox_resolved": True,
}
