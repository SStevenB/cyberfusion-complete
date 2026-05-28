# ingestion/connectors/stix_taxii.py
# STIX/TAXII connector (SCAFFOLDED) for OpenCTI / MISP / TAXII 2.1 feeds.
# Live fetch would poll a TAXII collection (api_root + collection_id) and pass
# returned bundles through the stix parser. STIX JSON upload is fully
# implemented today via the stix parser.

from ingestion.connectors.base import BaseConnector, ConnectorResult


class StixTaxiiConnector(BaseConnector):
    source_type = "stix"
    label = "STIX / TAXII"
    STATUS = "scaffolded"
    config_fields = ["taxii_url", "collection_id"]
    secret_fields = ["api_root"]   # treated as a credential-ish token here

    def test_connection(self, config, secret_values):
        missing = self.required_present(config, secret_values)
        if missing:
            return ConnectorResult(ok=False, message=f"Missing: {', '.join(missing)}.")
        return ConnectorResult(
            ok=True,
            message=("TAXII config present. Connector is scaffolded — upload a "
                     "STIX 2.1 JSON bundle to ingest threat intel now."))
