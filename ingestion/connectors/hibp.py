# ingestion/connectors/hibp.py
# HaveIBeenPwned domain-exposure connector (SCAFFOLDED).
# Live fetch would call the HIBP API /breacheddomain/{domain} with the API key,
# for a domain the user has verified ownership of. CSV upload fallback is fully
# implemented today via the hibp_csv parser.

from ingestion.connectors.base import BaseConnector, ConnectorResult


class HIBPConnector(BaseConnector):
    source_type = "hibp"
    label = "HaveIBeenPwned"
    STATUS = "scaffolded"
    config_fields = ["monitored_domain"]
    secret_fields = ["api_key"]

    def test_connection(self, config, secret_values):
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(ok=False, message=f"Missing: {', '.join(missing)}.")
        domain = (config or {}).get("monitored_domain", "")
        if "." not in domain:
            return ConnectorResult(ok=False, message="monitored_domain should be a domain like example.com")
        return ConnectorResult(
            ok=True,
            message=("API key + domain present. IMPORTANT: HIBP's domain-search "
                     "API requires you to have verified ownership of this domain. "
                     "Connector is scaffolded — use the CSV fallback to ingest a "
                     "HIBP domain export now."))
