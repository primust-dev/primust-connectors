"""
Primust Regulated Industry Connectors
======================================

Adapters for regulated platforms, each with an external verifier
that has a trust deficit and data that cannot be disclosed.

Python connectors (importable):
  - ComplyAdvantageConnector — AML entity screening
  - NiceActimizeConnector — AML transaction monitoring + SAR decisions
  - FicoBlazeConnector — FICO Blaze credit decisioning
  - IBMODMConnector — IBM ODM underwriting
  - UpToDateConnector — Wolters Kluwer clinical decision support
  - FicoFalconConnector — FICO Falcon fraud detection (PARTIAL fit)
  - PegaDecisioningConnector — Pega CDH next-best-action (PARTIAL fit)
  - GuidewireClaimCenterConnector — Guidewire ClaimCenter P&C claims
  - PurviewConnector — Microsoft Purview Copilot governance + DLP monitoring

Java spec/reference files (not importable — require Java SDK):
  - healthshare/HealthShareGovernanceAdapter.java — InterSystems HealthShare/IRIS
  - sapiens_decision/SapiensDecisionAdapter.java — Sapiens DECISION underwriting

C# spec/reference files (not importable — require C# SDK P10-E):
  - duck_creek/PrimustGovernanceExtension_DuckCreek.cs — Duck Creek Technologies
  - majesco/PrimustMajescoExtension.cs — Majesco CloudInsurer
  - sapiens_alis/PrimustAlisExtension_Sapiens.cs — Sapiens ALIS L&AH
"""

from primust_connectors.comply_advantage import ComplyAdvantageConnector
from primust_connectors.nice_actimize import NiceActimizeConnector
from primust_connectors.credit_brms import FicoBlazeConnector, IBMODMConnector
from primust_connectors.wolters_kluwer import UpToDateConnector
from primust_connectors.fico_falcon import FicoFalconConnector
from primust_connectors.pega_decisioning import PegaDecisioningConnector
from primust_connectors.guidewire import GuidewireClaimCenterConnector
from primust_connectors.purview import PurviewConnector

__version__ = "0.1.0"
__all__ = [
    "ComplyAdvantageConnector",
    "NiceActimizeConnector",
    "FicoBlazeConnector",
    "IBMODMConnector",
    "UpToDateConnector",
    "FicoFalconConnector",
    "PegaDecisioningConnector",
    "GuidewireClaimCenterConnector",
    "PurviewConnector",
]
