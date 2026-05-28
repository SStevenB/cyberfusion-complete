# ingestion/connectors/ — API connector scaffolding for configured sources.
#
# HONEST SCOPE NOTE (read this):
# These connectors define a clean, real interface (configure → test_connection
# → fetch) and validate credential/config presence. They are deliberately
# SCAFFOLDED, not wired to live vendor APIs, because a student project cannot
# verify live calls against real Tenable/Qualys/Entra tenants — faking those
# calls would be dishonest and un-demoable.
#
# For every connector, the manual CSV/JSON upload path is FULLY implemented and
# is the supported way to get real data in today. The connector interface is
# here so the architecture is real and a live fetch() can be dropped in later
# without touching the rest of the app.

from ingestion.connectors.base import BaseConnector, ConnectorResult
from ingestion.connectors.tenable import TenableConnector
from ingestion.connectors.qualys import QualysConnector
from ingestion.connectors.hibp import HIBPConnector
from ingestion.connectors.m365 import M365Connector
from ingestion.connectors.stix_taxii import StixTaxiiConnector

# Map source_type → connector class. Only types with a connector appear here.
CONNECTORS = {
    "tenable": TenableConnector,
    "qualys": QualysConnector,
    "hibp": HIBPConnector,
    "m365_signin": M365Connector,
    "stix": StixTaxiiConnector,
}


def get_connector(source_type: str):
    """Return an instance of the connector for a source type, or None."""
    cls = CONNECTORS.get(source_type)
    return cls() if cls else None
