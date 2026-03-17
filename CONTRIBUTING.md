# Contributing to Primust Connectors

Thank you for your interest in contributing a connector. This guide covers what a connector needs, how to structure it, and how to get it merged.

## The three-property fit filter

Every connector must pass the three-property test before inclusion:

1. **Regulated process** — the workflow is subject to external examination or litigation
2. **External verifier with trust deficit** — a regulator, counterparty, or auditor needs proof but can't access the system
3. **Data that can't be disclosed** — satisfying the verifier through disclosure would create legal, competitive, or privacy risk

Connectors that fail this filter are not included regardless of platform size. Partial fits (e.g., FICO Falcon, Pega CDH) are included and honestly flagged — we don't exclude them, but we don't oversell them either.

## Connector structure

Each connector is a Python module in `src/primust_connectors/`. A minimal connector needs:

### 1. FIT_VALIDATION dict

```python
FIT_VALIDATION = {
    "platform": "Vendor Platform Name",
    "category": "What it does",
    "fit": "STRONG",  # or "PARTIAL (reason)"
    "external_verifier": "Who needs proof",
    "trust_deficit": True,
    "data_sensitivity": "What can't be disclosed and why",
    "gep_value": "What the VPEC proves for the verifier",
    "proof_ceiling_today": "attestation",  # REST connectors are always attestation
    "proof_ceiling_post_java_sdk": "mathematical",  # or proof_ceiling_post_csharp_sdk
    "cross_run_consistency_applicable": True,
    "buildable_today": True,
    "regulatory_hooks": [
        "Specific regulation or standard",
    ],
}
```

Be honest about proof ceiling. REST/API connectors are Attestation — the vendor's internal logic is a black box at the API boundary. Only in-process SDK execution (Java/C#) can achieve Mathematical proof for deterministic computations.

### 2. Connector class

Follow the pattern in any existing connector (e.g., `guidewire.py` for the reference implementation):

```python
class YourConnector:
    def __init__(self, vendor_api_key: str, primust_api_key: str, ...):
        ...

    def register_manifests(self) -> None:
        """Register process manifests with Primust."""
        ...

    def new_pipeline(self) -> Pipeline:
        """Create a new governance pipeline."""
        ...
```

### 3. Privacy invariants

These are non-negotiable:

- **Raw data never transits to Primust.** Compute the commitment hash locally before any network call. Use `primust_artifact_core.commitment.commit()` or compute `sha256:` hashes directly.
- **`visibility="opaque"`** on all records containing regulated data.
- **PII exclusion.** Entity names, DOBs, addresses, patient IDs, card numbers, account numbers — these never appear in commitment fields. Commit only structural metadata (entity type, jurisdiction, search parameters, decision codes).
- **Vendor API errors produce gap records, not raised exceptions.** Fail-open: record the gap code and continue. Never silently drop a governance gap.

### 4. Gap codes

Define vendor-specific gap codes for error conditions:

```python
# In your connector:
try:
    response = self._client.post(url, json=payload)
    response.raise_for_status()
except httpx.HTTPStatusError as e:
    run.record(RecordInput(
        stage="your_stage",
        input={},
        output={"gap_code": "vendor_api_error", "status": e.response.status_code},
        proof_level="attestation",
        visibility="opaque",
    ))
    return YourResult(success=False, gap_code="vendor_api_error")
```

### 5. Framework tags

Add `regulatory_references` to manifest stages where applicable — these tie the governance record to specific regulations (e.g., `bsa_aml`, `hipaa_phi`, `ecoa_fair_lending`).

## Tests

Every connector needs tests in `tests/test_your_connector.py`. Required test categories:

### Privacy invariant tests (required)

```python
def test_raw_input_not_in_transmitted_payload(self):
    """Commitment hash transmitted, never raw input."""
    # Verify that sensitive input data appears nowhere in API call payloads
    ...

def test_pii_excluded_from_commitment(self):
    """PII fields must not appear in commitment."""
    ...
```

### Fit validation test (required)

```python
def test_fit_validation_passes(self):
    result = validate_fit(FIT_VALIDATION)
    assert result["fit_confirmed"] is True
    assert result["score"] == "3/3"
```

### Functional tests

Cover the main workflow paths: successful execution, vendor API errors (gap recording), and edge cases specific to your platform.

## Running tests

```bash
# Run your connector's tests
pytest tests/test_your_connector.py -v

# Run the full suite (must not break existing tests)
pytest tests/ -v
```

All 321+ existing tests must continue to pass.

## Adding to fit_validation.py

Import your `FIT_VALIDATION` dict in `src/primust_connectors/fit_validation.py` and add it to the `ALL_CONNECTORS` list.

## Adding to __init__.py

Export your connector class from `src/primust_connectors/__init__.py`.

## Java / C# connectors

For platforms that require in-process execution (JVM or .NET), create a spec file in the appropriate subdirectory:

- Java: `src/primust_connectors/<platform>/YourAdapter.java`
- C#: `src/primust_connectors/<platform>/YourExtension.cs`

These are reference implementations. Mark `buildable_today: False` in FIT_VALIDATION and note the required SDK in `sdk_required`.

## Submitting

1. Fork the repo
2. Create a branch: `git checkout -b add-<platform>-connector`
3. Add your connector, tests, fit validation entry, and `__init__.py` export
4. Run the full test suite: `pytest tests/ -v`
5. Open a PR with:
   - Platform name and category
   - External verifier and the trust deficit it addresses
   - Proof ceiling (be honest)
   - Test results

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
