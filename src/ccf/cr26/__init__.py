"""CR26 deliverable schemas — vendored and pinned by sha256.

``schemas/MANIFEST.json`` differs in shape from ``ccf.oscal.schemas.MANIFEST``:
here ``files`` maps filename to an *object* (``sha256``, ``schema_version``,
``title``, ``id``), not a bare sha256 string. FedRAMP versions each CR26
schema independently by ``$schemaVersion`` (semver), while the date in every
filename is the shared ruleset revision (``ruleset_version``) -- two levels of
versioning that a single string per file cannot express.

Task 2 fills this out with a real re-export surface (validation, loading).
"""
