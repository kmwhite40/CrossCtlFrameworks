"""Where a webhook may send: public HTTP(S) endpoints, not the platform's network.

A webhook makes Concord's server issue a POST to a URL a user chose. Without a
check that is server-side request forgery: a target on loopback, a private
range, or the link-local metadata service (169.254.169.254) is reachable from
the server and not from the user. Two checks, one rule:

* **On create** -- refuse a scheme other than http/https, credentials in the
  URL, a blocked host name, an IP literal in a blocked range, or a name that
  resolves to one. A name that does not resolve yet is accepted: it may be
  created before its DNS exists, and delivery re-checks.
* **On delivery** -- resolve again and refuse any blocked address, so a name
  that later points inward (DNS rebinding) is not followed. httpx does not
  follow redirects by default, and dispatch keeps it that way.

``CCF_WEBHOOK_ALLOW_PRIVATE_TARGETS=true`` admits private-range targets for an
on-premises deployment whose receivers are internal. Loopback, link-local and
metadata hosts stay refused regardless.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from ..config import get_settings

#: Host names that address the server itself or a cloud metadata service.
BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal", "metadata", "instance-data"})


def _always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.is_reserved and not ip.is_private)
    )


def blocked_address(ip_text: str) -> bool:
    """True if Concord must not send to this address."""
    ip = ipaddress.ip_address(ip_text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if _always_blocked(ip):
        return True
    return ip.is_private and not get_settings().webhook_allow_private_targets


def _resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError):
        return []


def _shape_refusal(url: str) -> tuple[str | None, str]:
    """(reason, host): what is wrong with the URL itself, before any lookup."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return "not a valid URL", ""
    host = (parts.hostname or "").rstrip(".").lower()
    if parts.scheme not in ("http", "https"):
        reason: str | None = "only http and https URLs are allowed"
    elif parts.username or parts.password:
        reason = "credentials may not be embedded in the URL"
    elif not host:
        reason = "the URL has no host"
    elif host in BLOCKED_HOSTS or host.endswith(".localhost"):
        reason = f"{host} addresses the server itself or a metadata service"
    else:
        reason = None
    return reason, host


def refusal(url: str, *, require_resolution: bool = False) -> str | None:
    """Why ``url`` may not receive webhooks, or None if it may.

    ``require_resolution`` is set at delivery: a name that does not resolve
    then cannot be sent to, and every address it resolves to must be allowed."""
    reason, host = _shape_refusal(url)
    if reason is not None:
        return reason
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        addresses = _resolve(host)
    if not addresses:
        return f"{host} does not resolve" if require_resolution else None
    bad = [a for a in addresses if blocked_address(a)]
    return f"{host} resolves to an address Concord does not send to ({bad[0]})" if bad else None
