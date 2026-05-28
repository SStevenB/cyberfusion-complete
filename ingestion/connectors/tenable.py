# ingestion/connectors/tenable.py
# Tenable.io / Tenable.sc connector (SCAFFOLDED).
# Live fetch would call the Tenable API (/vulns/export) with the access+secret
# keys, then feed rows through the vuln_csv parser logic. CSV upload fallback
# is fully implemented today via the vuln_csv parser.

from ingestion.connectors.base import BaseConnector, ConnectorResult


class TenableConnector(BaseConnector):
    source_type = "tenable"
    label = "Tenable"
    STATUS = "scaffolded"
    config_fields = ["base_url"]
    secret_fields = ["access_key", "secret_key"]

    def test_connection(self, config, secret_values):
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(ok=False, message=f"Missing: {', '.join(missing)}.")
        base = (config or {}).get("base_url", "")
        if not base.startswith("http"):
            return ConnectorResult(ok=False, message="base_url should start with https://")
        return ConnectorResult(
            ok=True,
            message=("Credentials present and base_url looks valid. Connector is "
                     "scaffolded — enable the CSV fallback to ingest Tenable "
                     "exports now (Export → CSV in Tenable)."))
