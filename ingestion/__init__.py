# ingestion/ — upload evidence ingestion layer
#
# Turns authorized security-evidence files uploaded by a user (nmap scans,
# vulnerability-scanner exports, asset inventories, breach exports) into the
# same normalized schema the rest of CyberFusion already uses.
#
# Design principle: parsers emit records in the EXACT shape that
# analysis/normalizer.py produces, so the existing correlation engine and
# risk scorer consume uploaded evidence with zero changes.
