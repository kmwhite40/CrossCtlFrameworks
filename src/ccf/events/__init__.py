"""The event bus: a transactional outbox and the consumers that drain it.

Consumers register themselves on import (``ccf.events.consumers.register``);
import each consumer module here so the registry is complete whenever the
package is: ``webhook``, ``notify_delivery`` and the derived views (``derived``).
"""

# Each import registers its consumers: ``webhook``, ``notify_delivery``, and the
# four derived views.
from . import derived, notify_delivery, webhooks  # noqa: F401
