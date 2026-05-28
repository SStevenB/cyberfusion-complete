# ingestion/connectors/qualys.py
# Qualys VMDR connector (SCAFFOLDED).
# Live fetch would call the Qualys API (/api/2.0/fo/asset/host/vm/detection)
# with basic auth, then map detections through the vuln parser logic. CSV
# upload fallback is fully implemented today.

from ingestion.connectors.base import BaseConnector, ConnectorResult


class QualysConnector(BaseConnector):
    source_type = "qualys"
    label = "Qualys"
    STATUS = "scaffolded"
    config_fields = ["base_url", "username"]
    secret_fields = ["password"]

    def test_connection(self, config, secret_values):
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(ok=False, message=f"Missing: {', '.join(missing)}.")
        return ConnectorResult(
            ok=True,
            message=("Credentials present. Connector is scaffolded — use the "
                     "CSV fallback to ingest Qualys VMDR exports now."))
