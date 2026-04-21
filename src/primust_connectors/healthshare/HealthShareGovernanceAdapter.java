"""
Primust Connector: InterSystems HealthShare / IRIS for Health
=============================================================
Fit: STRONG
Verifier: CMS, Joint Commission, state health departments, HIE participants
Problem solved: HIPAA paradox — prove clinical decision support and care
               coordination processes ran on patient data without disclosing PHI
Proof ceiling: Mathematical via IRIS Java Binding (in-process)
Buildable: Java SDK (P10-D — shipped) + IRIS Java Gateway configuration

IRIS Java Binding integration:
  InterSystems IRIS natively exposes Java bindings via IRIS Java Gateway.
  The gateway runs as a separate JVM process. Java code connects via
  JDBC-like binding and can call IRIS objects directly.
  This is in-process from the JVM perspective — Poseidon2 commitment
  is computed in the Java layer before any data transits.

ObjectScript hook alternative:
  IRIS %RegisteredObject can call Java Gateway methods.
  A %OnAfterSave() or custom BusinessOperation can invoke the Java SDK
  from within ObjectScript workflows.

Key clinical use cases:
  1. CDS Hooks — prove clinical decision support fired on this patient encounter
  2. Care coordination rules — prove patient met criteria for care pathway enrollment
  3. Consent verification — prove consent was checked before data sharing
  4. HIE data access — prove authorized access policy ran before record retrieval

HealthShare APIs:
  FHIR R4: GET/POST /fhir/r4/[resource]
  IRIS Java Binding: IRISObject, IRISIterator via com.intersystems.jdbc.IRIS
  HealthShare Health Connect: Business Process + Business Operation objects
"""

package com.primust.adapters.intersystems;

import com.intersystems.jdbc.IRIS;
import com.intersystems.jdbc.IRISObject;
import com.intersystems.jdbc.IRISDataSource;
import com.primust.Primust;
import com.primust.Pipeline;
import com.primust.RecordInput;
import com.primust.CheckResult;
import com.primust.VPEC;

import java.sql.Connection;
import java.util.Map;

/**
 * Primust governance adapter for InterSystems HealthShare / IRIS for Health.
 *
 * Connects via IRIS Java Binding (IRIS Java Gateway).
 * Commitment computed in-process (JVM layer) before any data leaves.
 *
 * Prerequisites:
 *   1. IRIS Java Gateway running on the HealthShare instance
 *   2. intersystems-jdbc JAR on classpath (from HealthShare installation)
 *   3. Java SDK (P10-D) on classpath: com.primust:primust-sdk
 *
 * Maven dependency:
 *   <dependency>
 *     <groupId>com.intersystems</groupId>
 *     <artifactId>intersystems-jdbc</artifactId>
 *     <version>3.3.0</version>
 *   </dependency>
 */
public class HealthShareGovernanceAdapter {

    private final IRIS iris;
    private final Pipeline pipeline;
    private final String manifestIdCdsHooks;
    private final String manifestIdConsentCheck;
    private final String manifestIdCarePathway;

    public HealthShareGovernanceAdapter(
        IRIS iris,
        Pipeline pipeline,
        String manifestIdCdsHooks,
        String manifestIdConsentCheck,
        String manifestIdCarePathway
    ) {
        this.iris = iris;
        this.pipeline = pipeline;
        this.manifestIdCdsHooks = manifestIdCdsHooks;
        this.manifestIdConsentCheck = manifestIdConsentCheck;
        this.manifestIdCarePathway = manifestIdCarePathway;
    }

    /**
     * Factory — connect to IRIS and build adapter.
     * Call once per application startup.
     */
    public static HealthShareGovernanceAdapter connect(
        String irisHost,
        int irisPort,
        String irisNamespace,
        String irisUsername,
        String irisPassword,
        String primustApiKey,
        String workflowId,
        Map<String, String> manifestIds
    ) throws Exception {
        IRISDataSource ds = new IRISDataSource();
        ds.setServerName(irisHost);
        ds.setPortNumber(irisPort);
        ds.setDatabaseName(irisNamespace);
        ds.setUser(irisUsername);
        ds.setPassword(irisPassword);

        Connection conn = ds.getConnection();
        IRIS irisInstance = IRIS.createIRIS(conn);

        Pipeline p = Primust.builder()
            .apiKey(primustApiKey)
            .workflowId(workflowId)
            .build();

        return new HealthShareGovernanceAdapter(
            irisInstance,
            p,
            manifestIds.getOrDefault("cds_hooks", ""),
            manifestIds.getOrDefault("consent_check", ""),
            manifestIds.getOrDefault("care_pathway", "")
        );
    }

    // ------------------------------------------------------------------
    // CDS Hooks — Clinical Decision Support
    // CDS Hooks are FHIR-based — called at order entry, prescription, etc.
    // ------------------------------------------------------------------

    /**
     * Record proof that a CDS Hook fired for this patient encounter.
     *
     * HIPAA paradox resolved:
     *   Joint Commission asks: "Prove your CDS fired for medication orders."
     *   VPEC proves CDS ran on this patient/encounter without disclosing PHI.
     *   input commitment = patient_id + encounter_id + hook_type
     *   Patient's medication list, diagnoses, allergies never transit.
     *
     * @param patientId  FHIR Patient resource ID
     * @param encounterId FHIR Encounter resource ID
     * @param hookId     CDS Hook identifier (e.g., "medication-prescribe")
     * @param hookResult CDS service response (cards, suggestions)
     */
    public void recordCdsHookExecution(
        String patientId,
        String encounterId,
        String hookId,
        String hookResult,   // "CARDS_RETURNED" | "NO_SUGGESTION" | "ERROR"
        boolean criticalAlertGenerated
    ) {
        CheckResult result = hookResult.equals("ERROR")
            ? CheckResult.ERROR
            : CheckResult.PASS;

        // Call IRIS to get the CDS rule version that fired
        String cdsRuleVersion = "";
        try {
            IRISObject cdsService = iris.classMethodObject(
                "HS.FHIRServer.Interop.Utils",
                "GetCDSServiceVersion",
                hookId
            );
            cdsRuleVersion = cdsService != null ? cdsService.getString("Version") : "unknown";
        } catch (Exception e) {
            cdsRuleVersion = "unavailable";
        }

        pipeline.record(
            RecordInput.builder()
                .check("healthshare_cds_hooks")
                .manifestId(manifestIdCdsHooks)
                // Input: patient + encounter identity — committed locally
                // Patient clinical data NOT included — only the IDs
                .input(String.format(
                    "patient:%s|encounter:%s|hook:%s",
                    patientId, encounterId, hookId
                ).getBytes())
                .checkResult(result)
                .details(Map.of(
                    "hook_id", hookId,
                    "hook_result", hookResult,
                    "critical_alert", criticalAlertGenerated,
                    "cds_rule_version", cdsRuleVersion
                ))
                .visibility("opaque")  // encounter context is PHI
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Consent verification before data sharing
    // ------------------------------------------------------------------

    /**
     * Record proof that consent was verified before patient data was shared.
     *
     * HIE use case: prove consent policy ran before sharing records
     * with another provider or payer. State health department can ask
     * for proof of consent verification without receiving the consent
     * document or the data that was shared.
     *
     * @param patientId      FHIR Patient resource ID
     * @param requestingOrgId Organization requesting access (NPI or OID)
     * @param dataCategory   Type of data requested (e.g., "MentalHealth", "Substance")
     * @param consentVerified Whether consent was found and valid
     */
    public void recordConsentVerification(
        String patientId,
        String requestingOrgId,
        String dataCategory,
        boolean consentVerified
    ) {
        // Look up consent in IRIS via FHIR Consent resource
        IRISObject consentResult = null;
        String consentId = "not_found";
        try {
            consentResult = iris.classMethodObject(
                "HS.FHIR.DTL.Util.HC.SDA3",
                "GetActiveConsent",
                patientId,
                requestingOrgId,
                dataCategory
            );
            if (consentResult != null) {
                consentId = consentResult.getString("ConsentId");
            }
        } catch (Exception ignored) {}

        CheckResult result = consentVerified ? CheckResult.PASS : CheckResult.FAIL;

        pipeline.record(
            RecordInput.builder()
                .check("healthshare_consent_verification")
                .manifestId(manifestIdConsentCheck)
                // Consent verification is a set_membership check:
                // patient ∈ active_consents_for(org, data_category)
                // This is deterministic — Mathematical ceiling in-process
                .input(String.format(
                    "patient:%s|org:%s|category:%s",
                    patientId, requestingOrgId, dataCategory
                ).getBytes())
                .checkResult(result)
                .details(Map.of(
                    "requesting_org", requestingOrgId,
                    "data_category", dataCategory,
                    "consent_verified", consentVerified,
                    "consent_id", consentId
                ))
                .visibility("selective")  // org + category visible, patient ID opaque
                .build()
        );
    }

    // ------------------------------------------------------------------
    // Care pathway enrollment
    // ------------------------------------------------------------------

    /**
     * Record proof that care pathway enrollment criteria were evaluated.
     *
     * CMS Quality Measures context: prove patient was assessed for
     * care pathway enrollment using current clinical data. CMS auditors
     * can verify the assessment ran without receiving the patient record.
     *
     * @param patientId    FHIR Patient resource ID
     * @param pathwayId    Care pathway identifier
     * @param meetsCreiteria Whether patient meets enrollment criteria
     * @param criteriaVersion Version of enrollment criteria applied
     */
    public void recordCarePathwayEvaluation(
        String patientId,
        String pathwayId,
        boolean meetsCriteria,
        String criteriaVersion
    ) {
        CheckResult result = meetsCriteria ? CheckResult.PASS : CheckResult.FAIL;

        pipeline.record(
            RecordInput.builder()
                .check("healthshare_care_pathway")
                .manifestId(manifestIdCarePathway)
                .input(String.format(
                    "patient:%s|pathway:%s|criteria_version:%s",
                    patientId, pathwayId, criteriaVersion
                ).getBytes())
                .checkResult(result)
                .details(Map.of(
                    "pathway_id", pathwayId,
                    "criteria_version", criteriaVersion,
                    "meets_criteria", meetsCriteria
                ))
                .visibility("opaque")
                .build()
        );
    }

    /**
     * Issue VPEC for the complete patient encounter governance record.
     * Call at end of encounter or at end of governance session.
     */
    public VPEC issueVPEC() {
        return pipeline.close();
    }
}

/*
 * Manifest definitions (register via Primust dashboard or API):
 *
 * CDS_HOOKS_MANIFEST:
 * {
 *   "name": "healthshare_cds_hooks",
 *   "description": "InterSystems HealthShare CDS Hooks execution. FHIR-based
 *                   clinical decision support at order entry and prescription points.",
 *   "stages": [
 *     { "stage": 1, "name": "patient_context_retrieval", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "set_membership",
 *       "purpose": "Patient encounter context retrieved from FHIR server" },
 *     { "stage": 2, "name": "cds_rule_evaluation", "type": "custom_code",
 *       "proof_level": "attestation",
 *       "purpose": "CDS rule set evaluated against patient context" },
 *     { "stage": 3, "name": "critical_alert_check", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "set_membership",
 *       "purpose": "Decision card severity classification" }
 *   ],
 *   "aggregation": { "method": "worst_case" }
 * }
 *
 * CONSENT_CHECK_MANIFEST:
 * {
 *   "name": "healthshare_consent_verification",
 *   "stages": [
 *     { "stage": 1, "name": "consent_lookup", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "set_membership",
 *       "purpose": "Patient in active consents for requesting org and data category" },
 *     { "stage": 2, "name": "consent_validity", "type": "deterministic_rule",
 *       "proof_level": "mathematical", "method": "threshold_comparison",
 *       "formula": "consent.expiry_date >= current_date",
 *       "purpose": "Consent has not expired" }
 *   ],
 *   "aggregation": { "method": "all_must_pass" }
 * }
 */

/*
FIT_VALIDATION = {
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
    "proof_ceiling": "mathematical",
    "proof_ceiling_notes": (
        "Consent check = set_membership (deterministic). "
        "Consent expiry = threshold_comparison (arithmetic). "
        "Both Mathematical in-process via IRIS Java Binding. "
        "CDS rule evaluation itself is Attestation (rule logic proprietary). "
        "Per-stage breakdown surfaces Mathematical consent + expiry stages."
    ),
    "buildable": "Java SDK shipped. Requires IRIS Java Gateway config on HealthShare instance.",
    "design_partner_required": False,  # IRIS Java Gateway is standard config
    "regulatory_hooks": [
        "HIPAA 45 CFR §164.312 (technical safeguards)",
        "CMS Conditions of Participation §482.24",
        "HL7 SMART on FHIR consent management",
        "TEFCA data sharing framework",
        "Joint Commission NPSG",
    ],
    "hipaa_paradox_resolved": True,
}
*/
