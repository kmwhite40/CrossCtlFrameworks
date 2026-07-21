"""Organization-scoped AI provider gateway.

This package is the secure LLM infrastructure layer: envelope-encrypted credential
storage (:mod:`ccf.ai.cipher`), a provider-neutral adapter interface with Anthropic
and OpenAI implementations (:mod:`ccf.ai.providers`), and the resolution gateway
(:mod:`ccf.ai.gateway`) that maps an organization to its configured provider, model,
and decrypted credential before making a call. Distinct from ``ccf.ai_actions`` (the
typed, approval-gated GRC action layer) which is a *consumer* of this gateway.
"""
