"""Baseline release of a small record-processing module."""

ALLOWED_DOMAINS = ("api.example.com",)
PERMISSIONS = ("read",)


def migrate(records):
    """The baseline keeps existing records unchanged."""
    return [dict(record) for record in records]


def fetch_target():
    return "https://api.example.com/v1/records"

