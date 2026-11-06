"""The event bus: a transactional outbox and the consumers that drain it.

Consumers register themselves on import (``ccf.events.consumers.register``);
import each consumer module here so the registry is complete whenever the
package is. The ``webhook`` consumer is the first.
"""

from . import webhooks  # noqa: F401  (registers the ``webhook`` consumer)
