"""The shape of a policy / plan / procedure template.

A template is text an organization adopts, not a description of what it has
done. So it carries **no implementation status, no traceability verdicts and no
product claims**: m365-docs-hub's versions printed "Implemented" 111 times and
asserted specific Microsoft services as fact for every tenant. Every value an
organization must choose -- a review period, a lockout threshold, a retention
window -- is a ``{{parameter}}``, rendered through ``ccf.ssp.odp.render``, so an
unset one prints as ``[ORGANIZATION-DEFINED: key]`` rather than a number
nobody chose.

Two context tokens are always available besides a template's own parameters:
``{{organization}}`` (the organization's name) and ``{{policy_owner}}``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

KINDS = ("policy", "plan", "procedure")
CONTEXT_TOKENS = ("organization", "policy_owner")


@dataclass(frozen=True)
class Parameter:
    """An organization-defined value the text depends on. No default: a
    default would be a value someone chose for every customer at once."""

    key: str
    label: str
    hint: str = ""


@dataclass(frozen=True)
class Section:
    heading: str
    body: str


@dataclass(frozen=True)
class Template:
    key: str
    title: str
    kind: str
    #: NIST SP 800-53 Rev. 5 family code (``AC``, ``IR`` ...), or ``PM``.
    family: str
    summary: str
    #: 800-53 Rev. 5 controls the document supports (the ``-1`` control first).
    controls: tuple[str, ...]
    #: NIST SP 800-171 Rev. 2 requirement ids (``3.1.1``) it supports.
    requirements_171: tuple[str, ...]
    parameters: tuple[Parameter, ...]
    sections: tuple[Section, ...]
    review_frequency: str = "annual"
    #: Where the text came from, for anyone auditing the library.
    provenance: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
