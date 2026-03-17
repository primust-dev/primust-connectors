# Primust Connectors

Governed execution adapters for regulated enterprise platforms.

```bash
pip install primust-connectors
```

Each connector wraps a regulated decisioning platform with [Primust](https://primust.com) VPEC issuance — proving governance ran without disclosing the data it ran on.

---

## What Problem This Solves

Regulated workflows have a structural problem: the party who needs proof (a regulator, reinsurer, or auditor) can't receive the data the process ran on. AML screenings can't disclose watchlist matching criteria. Clinical decision support can't share patient records. Insurance underwriting can't reveal rating factors that enable anti-selection.

Primust connectors instrument these workflows to produce **Verifiable Process Execution Credentials (VPECs)** — cryptographically signed proof that a defined process ran on specific data, with the data committed locally and never transmitted.

---

## Platform Support

### 7 Python REST Connectors — Built (321 tests)

All REST connectors are **Attestation ceiling** — the vendor's internal logic is a black box at the REST API boundary. Mathematical ceiling is achievable with Java/C# in-process SDKs running inside the vendor's runtime — see spec files for details.

#### Financial Services

| Platform | Use Case | Ceiling (REST) | Max (In-Process) | Tests |
|---|---|---|---|---|
| [ComplyAdvantage](#complyadvantage) | AML entity screening | Attestation | Attestation (permanent) | 48 |
| [NICE Actimize](#nice-actimize) | AML transaction monitoring + SAR | Witnessed (SAR) / Attestation (scoring) | Mathematical | 51 |
| [FICO Blaze Advisor](#fico-blaze) | Credit decisioning BRMS | Attestation | Mathematical | 41 (shared with ODM) |
| [IBM ODM](#ibm-odm) | Enterprise BRMS / underwriting | Attestation | Mathematical | 41 (shared with Blaze) |
| [FICO Falcon](#fico-falcon) | Card fraud detection | Attestation | Mathematical | 45 |
| [Pega CDH](#pega) | Next-best-action / regulated NBA | Attestation | Attestation (permanent) | 46 |

#### Clinical

| Platform | Use Case | Ceiling (REST) | Max (In-Process) | Tests |
|---|---|---|---|---|
| [Wolters Kluwer UpToDate](#uptodate) | Clinical decision support | Attestation | Mathematical | 46 |

#### Insurance

| Platform | Use Case | Ceiling (REST) | Max (In-Process) | Status |
|---|---|---|---|---|
| [Guidewire ClaimCenter](#guidewire) | P&C claims adjudication | **Attestation** | Mathematical | Python REST: **BUILT** (38 tests). Java in-process: spec only — requires Guidewire Studio. |

#### Specs Only (Java/C# — require vendor SDK licenses)

| Platform | Language | Notes |
|---|---|---|
| InterSystems HealthShare | Java | Requires IRIS Java Gateway |
| Duck Creek Technologies | C# | Requires DCT Extensions framework |
| Majesco CloudInsurer | C# | Requires Majesco extension framework |
| Sapiens DECISION | Java | Requires Sapiens Decision API |
| Sapiens ALIS | C# | Requires Sapiens ALIS SDK |

---

## Quickstart — ComplyAdvantage

```python
from primust_connectors import ComplyAdvantageConnector

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
# without receiving watchlist matching criteria
```

## Quickstart — NICE Actimize (SAR Determination)

```python
from primust_connectors import NiceActimizeConnector

connector = NiceActimizeConnector(
    actimize_server_url="https://actimize.yourbank.com",
    actimize_api_key="...",
    primust_api_key="pk_live_...",
)
connector.register_manifests()

p = connector.new_pipeline()
run = p.open()

review_session = connector.open_sar_review(
    pipeline=p,
    reviewer_key_id="analyst_key_001",
    min_review_seconds=300,
)

result = connector.record_sar_determination(
    pipeline=p,
    alert_id="alert_12345",
    transaction_data=transaction,    # committed locally — never transmitted
    determination="FILE",
    review_session=review_session,
    reviewer_signature="ed25519:...",
    rationale="Structuring pattern consistent with 31 CFR §1020.320",
)

vpec = run.close()
# Proof level: Witnessed
# Satisfies 31 CFR §1020.320 documentation requirements
```

---

## Platform Details

### ComplyAdvantage

**Verifier:** FinCEN, FCA, AUSTRAC
**The paradox:** Prove AML screening ran without disclosing watchlist matching criteria (revealing criteria enables circumvention)
**Proof ceiling:** Attestation (permanent — screening logic is proprietary)
**Gap codes:** `complyadvantage_api_error` (High), `complyadvantage_auth_failure` (Critical)

---

### NICE Actimize

**Verifier:** FinCEN, OCC, FCA — SAR filing authority
**The paradox:** Velocity and structuring thresholds that trigger SAR review are never disclosed; SAR contents are protected
**Proof ceiling:** Witnessed (SAR determination), Attestation (ML behavioral scoring — permanent)
**Regulatory hook:** 31 CFR §1020.320 SAR documentation
**Gap codes:** `actimize_api_error` (High), `actimize_auth_failure` (Critical)

---

### FICO Blaze Advisor

**Verifier:** CFPB, state AGs, plaintiff attorneys (ECOA / fair lending)
**The paradox:** Prove credit rules applied consistently without revealing decision criteria that could be gamed
**Proof ceiling today:** Attestation (REST API)
**Proof ceiling max:** Mathematical (in-process Java SDK)
**Gap codes:** `blaze_api_error` (High), `blaze_auth_failure` (Critical)

---

### IBM ODM

**Verifier:** CFPB, OCC, state regulators
**Unique capability:** `getRulesFired()` enables automatic per-rule manifest generation — strongest BRMS evidence fidelity
**Proof ceiling today:** Attestation (REST API)
**Proof ceiling max:** Mathematical (in-process Java SDK via IlrSessionFactory)
**Gap codes:** `odm_api_error` (High), `odm_auth_failure` (Critical)

---

### FICO Falcon

**Verifier:** OCC examiners, Visa/MC fraud program compliance
**Proof ceiling today:** Attestation (score computation is proprietary neural net)
**Proof ceiling max:** Mathematical (threshold comparison stages only, with in-process SDK)
**Note:** Score bands (low/medium/high) in output commitment — never raw scores
**Gap codes:** `falcon_api_error` (High), `falcon_auth_failure` (Critical)

---

### Pega CDH

**Verifier:** OCC, CFPB (regulated NBA), GDPR data subjects (Article 22)
**Proof ceiling:** Attestation (permanent — Pega engine is opaque)
**Best use case:** GDPR Article 22 automated decision disclosure; regulated credit limit / forbearance decisions
**Gap codes:** `pega_api_error` (High), `pega_auth_failure` (Critical)

---

### Wolters Kluwer UpToDate

**Verifier:** CMS, Joint Commission, malpractice insurers
**The paradox:** Prove drug interaction check ran on patient's medication list without disclosing PHI
**Proof ceiling today:** Attestation (interaction database is proprietary)
**Proof ceiling max:** Mathematical (dosing threshold stages — arithmetic bounds on published tables)
**Gap codes:** `wolters_kluwer_api_error` (High), `wolters_kluwer_auth_failure` (Critical)

---

### Guidewire ClaimCenter

**Verifier:** Reinsurers, Lloyd's syndicates, state DOI examiners
**The use case:** Cedant proves adjudication ran per policy terms without providing reinsurer the claim file
**Python REST connector:** BUILT — 38 tests. Calls the public Guidewire ClaimCenter Cloud API (standard REST, OAuth2/JWT). No Guidewire Studio required. **Attestation ceiling** — ClaimCenter's internal logic is a black box at the REST boundary.
**Java in-process plugin:** Spec only. Runs inside ClaimCenter's JVM. Requires Guidewire Studio + InsuranceSuite access. Achieves Mathematical ceiling. Cannot be built or tested without a Guidewire customer/partner relationship.
**Gap codes:** `guidewire_api_error` (High), `guidewire_auth_failure` (Critical)

---

## Architecture

Every connector follows the same three-property fit filter:

1. **Regulated process** — subject to external examination or litigation
2. **External verifier with trust deficit** — regulator or counterparty who needs proof but can't access the system
3. **Data that can't be disclosed** — satisfying the verifier through disclosure would create risk

Connectors that fail this filter are not included regardless of platform size.

**Invariants enforced in every connector:**

- Raw data never transits to Primust — commitment computed locally before any network call
- `visibility` defaults to `"opaque"` on all records — not configurable by caller for regulated data
- Vendor API failures record vendor-specific gap codes (`{platform}_api_error`) — never a silent drop
- Primust API failures are handled by SDK queue — queue loss records `system_unavailable` gap

---

## Gap Codes

Connector-specific gap codes are part of the canonical Primust gap taxonomy (45 total types). When a vendor platform API fails, the connector records a platform-specific gap — never suppresses it.

| Pattern | Severity | Trigger |
|---|---|---|
| `{platform}_api_error` | High | Vendor API unreachable or 5xx response |
| `{platform}_auth_failure` | Critical | Vendor API 401/403 — credential invalid or expired |

These are distinct from `system_error` (Primust-side processing failure) and `system_unavailable` (Primust API unreachable).

---

## Fit Validation

```python
from primust_connectors.fit_validation import print_summary

print_summary()
# Platform                         Fit      Tests  Ceiling (REST)  Max (SDK)
# ComplyAdvantage               STRONG        48   attestation            —
# NICE Actimize                 STRONG        51   attestation  mathematical
# FICO Blaze Advisor            STRONG        41   attestation  mathematical
# IBM ODM                       STRONG        41   attestation  mathematical
# FICO Falcon                  PARTIAL        45   attestation  mathematical
# Pega CDH                     PARTIAL        46   attestation            —
# Wolters Kluwer UpToDate       STRONG        46   attestation  mathematical
# Guidewire ClaimCenter         STRONG        38   attestation  mathematical*
#
# * Mathematical ceiling requires Java in-process SDK + Guidewire Studio license
```

---

## Contributing

Connectors for additional regulated platforms welcome. A connector needs:

- A `FIT_VALIDATION` dict declaring fit level, external verifier, proof ceiling, and regulatory hooks
- Honest fit assessment — partial fits are included and flagged
- Privacy invariant: input committed locally before any external API call
- Tests covering the commitment invariant (raw input must not appear in any transmitted payload)
- Platform-specific gap codes following `{platform}_api_error` / `{platform}_auth_failure` pattern

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## License

Apache-2.0

---

[Primust SDK](https://github.com/primust-dev/primust-sdk) · [Docs](https://docs.primust.com) · [Verify](https://verify.primust.com)
