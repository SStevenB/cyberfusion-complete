# api/ — FastAPI backend that exposes the existing CyberFusion Python pipeline
# as JSON endpoints for the React frontend. No pipeline logic is reimplemented
# here; this layer only calls functions that already exist in analysis/,
# ingestion/, and build_demo.py.
