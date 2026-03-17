# Primust Connectors

Governed execution adapters for regulated enterprise platforms.

```bash
pip install primust-connectors
```

Each connector wraps a regulated decisioning platform with [Primust](https://primust.com) VPEC issuance — proving governance ran without disclosing the data it ran on.

## What problem this solves

Regulated workflows have a structural problem: the party who needs proof (a regulator, reinsurer, or auditor) can't receive the data the process ran on. AML screenings can't disclose watchlist matching criteria. Clinical decision support can't share patient records. Insurance underwriting can't reveal rating factors that enable anti-selection.

Primust connectors instrument these workflows to produce **Verifiable Process Execution Credentials (VPECs)** — cryptographically signed proof that a defined process ran on specific data, with the data committed locally and never transmitted.

## Platform support

### Financial Services

| Platform | Use case | Ceiling (today) | Max (in-process SDK) | Status |
|---|---|---|---|---|
| [ComplyAdvantage](#complyadvantage) | AML entity screening | Attestation | Attestation | Python — ready |
| [NICE Actimize](#nice-actimize) | AML transaction monitoring + SAR | Attestation | Mathematical | Python — ready |
| [FICO Blaze Advisor](#fico-blaze) | Credit decisioning BRMS | Attestation | Mathematical | Python — ready |
| [IBM ODM](#ibm-odm) | Enterprise BRMS / underwriting | Attestation | Mathematical | Python — ready |
| [FICO Falcon](#fico-falcon) | Card fraud detection | Attestation | Mathematical | Python — ready |
| [Pega CDH](#pega) | Next-best-action / regulated NBA | Attestation | Attestation (permanent) | Python — ready |

### Clinical

| Platform | Use case | Ceiling (today) | Max (in-process SDK) | Status |
|---|---|---|---|---|
| [Wolters Kluwer UpToDate](#uptodate) | Clinical decision support | Attestation | Mathematical | Python — ready |
| [InterSystems HealthShare](#healthshare) | Clinical governance / HIE | Attestation | Mathematical | Java spec |

### Insurance

| Platform | Use case | Ceiling (today) | Max (in-process SDK) | Status |
|---|---|---|---|---|
| [Guidewire](#guidewire) | P&C claims adjudication | Attestation | Mathematical | Java spec |
| [Duck Creek Technologies](#duck-creek) | P&C rating + claims | Attestation | Mathematical | C# spec |
| [Majesco CloudInsurer](#majesco) | P&C / L&AH rating + claims | Attestation | Mathematical | C# spec |
| [Sapiens DECISION](#sapiens-decision) | Insurance underwriting rules | Attestation | Mathematical | Java spec |
| [Sapiens ALIS](#sapiens-alis) | L&AH — suitability + underwriting | Attestation | Mathematical | C# spec |

**Ceiling (today)** is the proof level achievable with the current REST/API connectors. All REST connectors are Attestation — the vendor's internal logic is a black box at the API boundary.

**Max (in-process SDK)** is the theoretical maximum when running inside the vendor's JVM/.NET process with the Java/C# SDK. In-process execution enables Mathematical proof via ZK circuits for deterministic computations.

**Status** indicates buildable status. Python connectors are runnable today (321 tests passing). Java/C# spec files are reference implementations that require the respective SDK (`com.primust:primust-sdk` or `Primust.SDK`).

## Installation

```bash
pip install primust-connectors
```

Requires `primust>=0.1.0` and `httpx>=0.27.0`.

## Quickstart — ComplyAdvantage

```python
from primust_connectors import ComplyAdvantageConnector
import primust

connector = ComplyAdvantageConnector(
    ca_api_key="ca_live_...",
    primust_api_key="pk_live_...",
)
connector.register_manifests()

p = connector.new_pipeline()
run = p.open()

result = connector.screen_entity(
    pipeline=p,
    entity_name="Acme Corp",
    entity_data={"name": "Acme Corp", "country": "US"},
)

vpec = run.close()
# vpec proves screening ran on this entity
# Provide to FinCEN examiner — they verify at verify.primust.com
# without receiving your watchlist matching criteria
```

## Quickstart — NICE Actimize (SAR determination)

```python
from primust_connectors import NiceActimizeConnector

connector = NiceActimizeConnector(
    actimize_server_url="https://actimize.yourbank.com",
    actimize_api_key="...",
    primust_api_key="pk_live_...",
)
connector.register_manifests()

p = connector.new_pipeline()

# Open a human review session for Witnessed level
review_session = connector.open_sar_review(
    pipeline=p,
    reviewer_key_id="analyst_key_001",
    min_review_seconds=300,
)

result = connector.record_sar_determination(
    pipeline=p,
    alert_id="alert_12345",
    transaction_data=transaction,   # committed locally
    determination="FILE",
    review_session=review_session,
    reviewer_signature="ed25519:...",
    rationale="Structuring pattern consistent with 31 CFR §1020.320",
)

vpec = run.close()
# Proof level: Witnessed
# Satisfies 31 CFR §1020.320 documentation requirements
```

## Platform details

### ComplyAdvantage

**Verifier:** FinCEN, FCA, AUSTRAC  
**The paradox:** Prove AML screening ran without disclosing watchlist matching criteria (revealing criteria enables circumvention)  
**Proof ceiling:** Attestation  
**Buildable:** Now

```python
from primust_connectors import ComplyAdvantageConnector
```

---

### NICE Actimize

**Verifier:** FinCEN, OCC, FCA — SAR filing authority  
**The paradox:** Velocity and structuring thresholds that trigger SAR review are never disclosed; SAR contents are protected  
**Proof ceiling:** Witnessed (SAR determination), Attestation (ML behavioral scoring — permanent)  
**Buildable:** Now  
**Regulatory hook:** 31 CFR §1020.320 SAR documentation

```python
from primust_connectors import NiceActimizeConnector
```

---

### FICO Blaze Advisor

**Verifier:** CFPB, state AGs, plaintiff attorneys (ECOA / fair lending)
**The paradox:** Prove credit rules applied consistently without revealing the decision criteria that could be gamed
**Proof ceiling today:** Attestation (REST API)
**Proof ceiling max:** Mathematical (in-process Java SDK)
**Cross-run consistency:** Detects discriminatory treatment from commitment hashes alone — never sees applicant data
**Buildable:** Now (Attestation)

```python
from primust_connectors import FicoBlazeConnector
```

---

### IBM ODM

**Verifier:** CFPB, OCC, state regulators
**Unique capability:** `getRulesFired()` enables automatic per-rule manifest generation — strongest BRMS evidence fidelity
**Proof ceiling today:** Attestation (REST API)
**Proof ceiling max:** Mathematical (in-process Java SDK)
**Buildable:** Now (Attestation)

```python
from primust_connectors import IBMODMConnector
```

---

### FICO Falcon

**Verifier:** OCC examiners, Visa/MC fraud program compliance
**Fit:** Partial — primary value for OCC examination and card network compliance
**Proof ceiling today:** Attestation (score computation is proprietary neural net)
**Proof ceiling max:** Mathematical (threshold comparison stages only, with in-process SDK)
**Note:** Score bands (low/medium/high) in output commitment, never raw scores. Threshold values not disclosed.
**Buildable:** Now

```python
from primust_connectors import FicoFalconConnector
```

---

### Pega CDH

**Verifier:** OCC, CFPB (regulated NBA), GDPR data subjects (Article 22)  
**Fit:** Partial — only valuable for regulated NBA deployments. Internal marketing workflows have no external verifier problem.  
**Proof ceiling:** Attestation (permanent — Pega engine is opaque)  
**Best use case:** GDPR Article 22 automated decision disclosure; regulated credit limit / forbearance decisions  
**Buildable:** Now

```python
from primust_connectors import PegaDecisioningConnector
```

---

### Wolters Kluwer UpToDate

**Verifier:** CMS, Joint Commission, malpractice insurers
**The paradox:** Prove drug interaction check ran on patient's medication list without disclosing PHI
**Proof ceiling today:** Attestation (interaction database is proprietary)
**Proof ceiling max:** Mathematical (dosing threshold stages — arithmetic bounds on published tables)
**Buildable:** Now

```python
from primust_connectors import UpToDateConnector
```

---

### InterSystems HealthShare

**Verifier:** CMS, Joint Commission, HIE participants, state health departments
**The paradox:** HIPAA — prove clinical governance ran on patient data without disclosing PHI
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (consent verification = set membership, expiry = threshold comparison)
**Status:** Java spec — requires Java SDK + IRIS Java Gateway configuration

---

### Guidewire

**Verifier:** Reinsurers, Lloyd's syndicates, state DOI examiners
**The use case:** Cedant proves adjudication ran per policy terms without providing reinsurer the claim file
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (all stages deterministic arithmetic)
**Status:** Java spec — requires Java SDK + Guidewire Studio license

---

### Duck Creek Technologies

**Verifier:** State insurance commissioners, reinsurers
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (DCT Extensions in-process)
**Status:** C# spec — requires C# SDK + DCT Extensions framework

---

### Majesco CloudInsurer

**Verifier:** State insurance commissioners, reinsurers
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (Majesco extension framework in-process)
**Status:** C# spec — requires C# SDK

---

### Sapiens DECISION

**Verifier:** State insurance commissioners, Lloyd's syndicates, reinsurers
**The use case:** Prove rating factors applied consistently across book — fair underwriting proof without disclosing applications
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (in-process Java via Sapiens Decision API)
**Status:** Java spec — requires Java SDK

---

### Sapiens ALIS

**Verifier:** State insurance departments, SEC/FINRA (variable products), CMS
**Unique angle:** FINRA Rule 2111 / Reg BI suitability — prove annuity suitability assessment ran without disclosing customer financial profile
**Proof ceiling today:** Attestation (spec only)
**Proof ceiling max:** Mathematical (suitability threshold comparisons are arithmetic)
**Status:** C# spec — requires C# SDK

---

## Fit validation

```python
from primust_connectors.fit_validation import print_summary

print_summary()
# Platform                           Fit  Score  Ready  Ceiling (today)        Max (SDK)
# ComplyAdvantage                 STRONG    3/3      Y      attestation                —
# NICE Actimize                   STRONG    3/3      Y      attestation     mathematical
# FICO Blaze Advisor              STRONG    3/3      Y      attestation     mathematical
# IBM Operational Decision Mgr    STRONG    3/3      Y      attestation     mathematical
# Wolters Kluwer UpToDate         STRONG    3/3      Y            mixed     mathematical
# FICO Falcon                    PARTIAL    3/3      Y      attestation     mathematical
# Pega Customer Decision Hub     PARTIAL    3/3      Y      attestation                —
# Guidewire ClaimCenter           STRONG    3/3      N      attestation     mathematical
# InterSystems HealthShare        STRONG    3/3      N      attestation     mathematical
# Sapiens DECISION                STRONG    3/3      N      attestation     mathematical
# Duck Creek Technologies         STRONG    3/3      N      attestation     mathematical
# Majesco CloudInsurer            STRONG    3/3      N      attestation     mathematical
# Sapiens ALIS                    STRONG    3/3      N      attestation     mathematical
```

## Architecture

Every connector follows the same three-property fit filter:

1. **Regulated process** — subject to external examination or litigation
2. **External verifier with trust deficit** — regulator or counterparty who needs proof but can't access the system
3. **Data that can't be disclosed** — satisfying the verifier through disclosure would create risk

Connectors that fail this filter are not included regardless of platform size.

**Invariants enforced in every connector:**
- Raw data never transits to Primust — commitment computed locally before any network call
- Visibility defaults to `opaque` for all regulated data
- NDA audit path available for regulators requiring full data under controlled disclosure
- `system_unavailable` gap recorded honestly if Primust API unreachable — never silent drop

## Contributing

Connectors for additional regulated platforms welcome. A connector needs:
- A `FIT_VALIDATION` dict declaring fit level, external verifier, proof ceiling, and regulatory hooks
- Honest fit assessment — partial fits are included and flagged, not excluded
- Privacy invariant: input committed locally before any external API call
- Tests covering the commitment invariant (raw input must not appear in any transmitted payload)

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

Apache 2.0

---

[Primust SDK](https://github.com/primust-dev/sdk-python) · [Docs](https://docs.primust.com) · [Verify](https://verify.primust.com)
