# ingestion/connectors/m365.py
# Microsoft 365 / Entra ID sign-in risk connector (SCAFFOLDED).
# Live fetch would use Microsoft Graph (/identityProtection/riskyUsers and
# /auditLogs/signIns) with an app registration (tenant_id/client_id/secret).
# The full OAuth app-registration flow is out of scope for this phase; the CSV
# upload fallback is fully implemented today via the m365_csv parser.

from ingestion.connectors.base import BaseConnector, ConnectorResult


class M365Connector(BaseConnector):
    source_type = "m365_signin"
    label = "Microsoft 365 / Entra"
    STATUS = "scaffolded"
    config_fields = ["tenant_id", "client_id"]
    secret_fields = ["client_secret"]

    def test_connection(self, config, secret_values):
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(ok=False, message=f"Missing: {', '.join(missing)}.")
        return ConnectorResult(
            ok=True,
            message=("App-registration fields present. Live Microsoft Graph "
                     "integration (OAuth) is scaffolded for a future phase — "
                     "use the CSV fallback (Entra → Sign-in logs → Export) now."))
