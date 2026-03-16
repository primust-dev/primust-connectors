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
Primust Connectors — Fit validation tests.

All 13 connectors must pass the three-property filter:
  1. Regulated process (has regulatory_hooks)
  2. External verifier with trust deficit
  3. Data that can't be disclosed

Note: FICO Falcon and Pega CDH pass 3/3 but have PARTIAL fit declarations.
Passing the filter means the properties exist; the fit_declared field
preserves the honest governance value assessment.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from primust_connectors.fit_validation import (
    ALL_CONNECTORS,
    validate_fit,
)


class TestFitValidation:
    def test_all_connectors_pass_three_property_filter(self):
        """All 13 connectors must pass the three-property GEP fit test."""
        for connector in ALL_CONNECTORS:
            result = validate_fit(connector)
            assert result["fit_confirmed"], (
                f"{result['platform']} failed fit validation: "
                f"score={result['score']}, "
                f"regulated={result['prop1_regulated_process']}, "
                f"verifier={result['prop2_external_verifier_trust_deficit']}, "
                f"data={result['prop3_data_cannot_be_disclosed']}"
            )

    def test_exactly_13_connectors_registered(self):
        """Exactly 13 connectors in the validation set."""
        assert len(ALL_CONNECTORS) == 13

    def test_each_connector_has_required_fields(self):
        """Each connector dict has the minimum required fields."""
        required_fields = [
            "platform",
            "external_verifier",
            "trust_deficit",
            "regulatory_hooks",
        ]
        for connector in ALL_CONNECTORS:
            for field in required_fields:
                assert field in connector, (
                    f"{connector.get('platform', 'unknown')} missing field: {field}"
                )

    def test_buildable_today_connectors(self):
        """At least 7 connectors are buildable today (Python SDK)."""
        buildable = [c for c in ALL_CONNECTORS if c.get("buildable_today")]
        assert len(buildable) >= 7, (
            f"Only {len(buildable)} connectors buildable today, expected >= 7"
        )

    def test_partial_fit_connectors_flagged(self):
        """FICO Falcon and Pega have PARTIAL fit — honest characterization preserved."""
        partial = [c for c in ALL_CONNECTORS if "PARTIAL" in str(c.get("fit", ""))]
        assert len(partial) == 2, f"Expected 2 PARTIAL fit connectors, got {len(partial)}"
        platforms = {c["platform"] for c in partial}
        assert "FICO Falcon" in platforms
        assert "Pega Customer Decision Hub" in platforms

    def test_guidewire_requires_design_partner(self):
        """Guidewire connector requires design partner."""
        guidewire = [c for c in ALL_CONNECTORS if "Guidewire" in c["platform"]]
        assert len(guidewire) == 1
        assert guidewire[0]["design_partner_required"] is True
        assert guidewire[0]["buildable_today"] is False
