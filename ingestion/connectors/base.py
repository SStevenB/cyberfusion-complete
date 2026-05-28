# ingestion/connectors/base.py
#
# The connector interface every API-backed source implements. Keeping this
# small and explicit means a future live integration only has to fill in
# fetch() — the dashboard, registry, and provenance plumbing already work.

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ConnectorResult:
    """Standard return type for a connector test / fetch."""
    ok: bool = False
    message: str = ""
    records: List[Dict[str, Any]] = field(default_factory=list)
    records_meta: Dict[str, Any] = field(default_factory=dict)


class BaseConnector:
    """
    Base class for API connectors.

    Lifecycle:
        connector = SomeConnector()
        result = connector.test_connection(config, secrets)   # validate creds
        result = connector.fetch(config, secrets)             # pull data

    Subclasses set STATUS to "implemented" or "scaffolded" so the UI can label
    them honestly.
    """
    source_type: str = "base"
    label: str = "Base Connector"
    STATUS: str = "scaffolded"      # "implemented" | "scaffolded"
    # config fields stored in workspace (non-secret) vs secret fields (keychain)
    config_fields: List[str] = []
    secret_fields: List[str] = []

    def required_present(self, config: Dict[str, Any], secret_values: Dict[str, str]) -> List[str]:
        """Return a list of any required fields that are missing."""
        missing = []
        for f in self.config_fields:
            if not (config or {}).get(f):
                missing.append(f)
        for f in self.secret_fields:
            if not (secret_values or {}).get(f):
                missing.append(f)
        return missing

    def test_connection(self, config: Dict[str, Any], secret_values: Dict[str, str]) -> ConnectorResult:
        """
        Default scaffolded behaviour: verify required config/secrets are present
        and report readiness. Live subclasses override this to make a real
        lightweight API call (e.g. an auth/ping endpoint).
        """
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(
                ok=False,
                message=f"Missing required field(s): {', '.join(missing)}.")
        if self.STATUS == "scaffolded":
            return ConnectorResult(
                ok=True,
                message=("Configuration looks complete. This connector is "
                         "scaffolded — live API fetch is not enabled in this "
                         "build; use the CSV/file upload fallback to ingest "
                         "real data."))
        return ConnectorResult(ok=True, message="Connection OK.")

    def fetch(self, config: Dict[str, Any], secret_values: Dict[str, str]) -> ConnectorResult:
        """
        Pull data from the source. Scaffolded connectors return ok=False with a
        clear pointer to the working upload path.
        """
        return ConnectorResult(
            ok=False,
            message=(f"The {self.label} live connector is scaffolded, not yet "
                     f"wired to the vendor API. Use the manual file-upload mode "
                     f"for this source — it is fully implemented."))
