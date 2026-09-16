"""Per-provider posture check definitions and their evaluation logic.

A check and how to judge it are one thing, so they live together here rather
than the definition sitting apart from the function that reads it. Transport
stays in the connector: these modules never make a network call, which is what
makes every evaluator a pure unit test against a recorded provider shape.

P2b relocates the definitions into ``packs/``; the evaluators stay as named
functions the pack references by key, so that move is a relocation rather than
a redesign.
"""

from __future__ import annotations
