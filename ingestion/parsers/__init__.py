# ingestion/parsers/ — one parser per supported upload file type.
# Each parser exposes:
#   detect(filename, text) -> bool      # is this file my type?
#   parse(text, filename) -> ParseResult  # records + errors + summary
