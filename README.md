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

| Platform | Use case | Proof ceiling | SDK |
|---|---|---|---|
| [ComplyAdvantage](#complyadvantage) | AML entity screening | Attestation | Python |
| [NICE Actimize](#nice-actimize) | AML transaction monitoring + SAR | Witnessed | Python |
| [FICO Blaze Advisor](#fico-blaze) | Credit decisioning BRMS | Mathematical | Python + Java |
| [IBM ODM](#ibm-odm) | Enterprise BRMS / underwriting | Mathematical | Python + Java |
| [FICO Falcon](#fico-falcon) | Card fraud detection | Attestation (Mathematical threshold) | Python |
| [Pega CDH](#pega) | Next-best-action / regulated NBA | Attestation | Python |

### Clinical

| Platform | Use case | Proof ceiling | SDK |
|---|---|---|---|
| [Wolters Kluwer UpToDate](#uptodate) | Clinical decision support | Mathematical | Python |
| [InterSystems HealthShare](#healthshare) | Clinical governance / HIE | Mathematical | Java (spec) |

### Insurance

| Platform | Use case | Proof ceiling | SDK |
|---|---|---|---|
| [Guidewire](#guidewire) | P&C claims adjudication | Mathematical | Java (spec) |
| [Duck Creek Technologies](#duck-creek) | P&C rating + claims | Mathematical | C# (spec) |
| [Majesco CloudInsurer](#majesco) | P&C / L&AH rating + claims | Mathematical | C# (spec) |
| [Sapiens DECISION](#sapiens-decision) | Insurance underwriting rules | Mathematical | Java (spec) |
| [Sapiens ALIS](#sapiens-alis) | L&AH — suitability + underwriting | Mathematical | C# (spec) |

**Proof ceiling** is the maximum achievable proof level for that platform. "Mathematical" means a ZK circuit can verify the computation — the verifier has cryptographic proof, not just an attestation. "Attestation" means the process is observed at the API boundary.

**SDK** indicates buildable status. Python connectors are runnable today. Java/C# spec files require the respective SDK (`com.primust:primust-sdk` or `Primust.SDK`) which are available separately.

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
**Proof ceiling:** Mathematical (in-process Java) / Attestation (REST)  
**Cross-run consistency:** Detects discriminatory treatment from commitment hashes alone — never sees applicant data  
**Buildable:** Now (Attestation), Mathematical with Java SDK

```python
from primust_connectors import FicoBlazeConnector
```

---

### IBM ODM

**Verifier:** CFPB, OCC, state regulators  
**Unique capability:** `getRulesFired()` enables automatic per-rule manifest generation — strongest BRMS evidence fidelity  
**Proof ceiling:** Mathematical (in-process Java)  
**Buildable:** Now (Attestation), Mathematical with Java SDK

```python
from primust_connectors import IBMODMConnector
```

---

### FICO Falcon

**Verifier:** OCC examiners, Visa/MC fraud program compliance  
**Fit:** Partial — primary value for OCC examination and card network compliance  
**Proof ceiling:** Attestation (score computation permanent), Mathematical (threshold comparison stages)  
**Note:** Threshold values not disclosed — revealing enables score gaming. Mathematical proof proves comparison ran correctly without disclosing thresholds.  
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
**Proof ceiling:** Mathematical (dosing threshold stages — arithmetic bounds on published tables)  
**Buildable:** Now

```python
from primust_connectors import UpToDateConnector
```

---

### InterSystems HealthShare

**Verifier:** CMS, Joint Commission, HIE participants, state health departments  
**The paradox:** HIPAA — prove clinical governance ran on patient data without disclosing PHI  
**Proof ceiling:** Mathematical (consent verification = set membership, expiry = threshold comparison)  
**Status:** Java spec — requires Java SDK + IRIS Java Gateway configuration

---

### Guidewire

**Verifier:** Reinsurers, Lloyd's syndicates, state DOI examiners  
**The use case:** Cedant proves adjudication ran per policy terms without providing reinsurer the claim file  
**Proof ceiling:** Mathematical (all stages deterministic arithmetic)  
**Status:** Java spec — requires Java SDK + Guidewire Studio license

---

### Duck Creek Technologies

**Verifier:** State insurance commissioners, reinsurers  
**Proof ceiling:** Mathematical (DCT Extensions in-process)  
**Status:** C# spec — requires C# SDK + DCT Extensions framework

---

### Majesco CloudInsurer

**Verifier:** State insurance commissioners, reinsurers  
**Proof ceiling:** Mathematical (Majesco extension framework in-process)  
**Status:** C# spec — requires C# SDK

---

### Sapiens DECISION

**Verifier:** State insurance commissioners, Lloyd's syndicates, reinsurers  
**The use case:** Prove rating factors applied consistently across book — fair underwriting proof without disclosing applications  
**Proof ceiling:** Mathematical (in-process Java via Sapiens Decision API)  
**Status:** Java spec — requires Java SDK

---

### Sapiens ALIS

**Verifier:** State insurance departments, SEC/FINRA (variable products), CMS  
**Unique angle:** FINRA Rule 2111 / Reg BI suitability — prove annuity suitability assessment ran without disclosing customer financial profile  
**Proof ceiling:** Mathematical (suitability threshold comparisons are arithmetic)  
**Status:** C# spec — requires C# SDK

---

## Fit validation

```python
from primust_connectors.fit_validation import print_summary

print_summary()
# Platform             | Fit      | Proof ceiling | Buildable
# ComplyAdvantage      | STRONG   | attestation   | now
# NICE Actimize        | STRONG   | witnessed     | now
# FICO Blaze           | STRONG   | mathematical  | now
# IBM ODM              | STRONG   | mathematical  | now
# UpToDate             | STRONG   | mathematical  | now
# Guidewire            | STRONG   | mathematical  | design partner
# HealthShare          | STRONG   | mathematical  | java sdk
# Sapiens DECISION     | STRONG   | mathematical  | java sdk
# Duck Creek           | STRONG   | mathematical  | c# sdk
# Majesco              | STRONG   | mathematical  | c# sdk
# Sapiens ALIS         | STRONG   | mathematical  | c# sdk
# FICO Falcon          | PARTIAL  | attestation   | now
# Pega CDH             | PARTIAL  | attestation   | now
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
