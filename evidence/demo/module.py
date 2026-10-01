"""Candidate release of a small record-processing module."""

ALLOWED_DOMAINS = ("api.example.com",)
PERMISSIONS = ("read",)


def migrate(records):
    """Preserve all existing keys and add an optional schema marker."""
    return [{**record, "schema_version": record.get("schema_version", 2)} for record in records]


def fetch_target():
    return "https://api.example.com/v1/records"
