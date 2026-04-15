"""Concord Reader — SQLite-backed single-file distribution.

Used by the PyInstaller-frozen `.exe` so analysts can browse the NIST catalog
without Docker or Postgres. Operational write flows are gated off via
`settings.readonly`.
"""
