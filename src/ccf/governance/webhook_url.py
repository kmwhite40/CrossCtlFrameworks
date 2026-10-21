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

#: Never a webhook target, whatever ``webhook_allow_private_targets`` says:
#: link-local (incl. 169.254.169.254), carrier-grade NAT, cloud metadata
#: addresses, and the NAT64 local-use prefix.
ALWAYS_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.0.0/16",
        "100.64.0.0/10",
        "100.100.100.200/32",
        "fd00:ec2::254/128",
        "64:ff9b:1::/48",
        "fe80::/10",
    )
)

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V4_COMPAT = ipaddress.ip_network("::/96")

IP = ipaddress.IPv4Address | ipaddress.IPv6Address


def _embedded_v4(ip: IP) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries, if it is one of the forms
    that route to it: IPv4-mapped, NAT64, 6to4, Teredo or IPv4-compatible."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64 or (ip in _V4_COMPAT and int(ip) > 1):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    return None


def blocked_address(ip_text: str) -> bool:
    """True if Concord must not send to this address.

    An allowlist, not a blocklist: the address must be globally routable,
    except a private-range address when the operator has opted in. Any IPv6
    form that carries an IPv4 address is judged by that IPv4 address."""
    ip: IP = ipaddress.ip_address(ip_text)
    inner = _embedded_v4(ip)
    candidates: list[IP] = [ip] if inner is None else [ip, inner]
    for c in candidates:
        if any(c in net for net in ALWAYS_BLOCKED if c.version == net.version):
            return True
        if c.is_loopback or c.is_link_local or c.is_multicast or c.is_unspecified:
            return True
    target = inner or ip
    if target.is_global:
        return False
    return not (target.is_private and get_settings().webhook_allow_private_targets)


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
    try:
        # ``.port`` raises for ``:abc`` or ``:99999``; checked here, a URL
        # accepted on create can always be delivered (or refused) later.
        parts.port  # noqa: B018
    except ValueError:
        return "the URL's port is not a number from 0 to 65535", host
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


def _checked(url: str, *, require_resolution: bool) -> tuple[str | None, str, list[str]]:
    """(refusal, host, addresses) from **one** resolution of the host.

    Everything downstream uses these addresses; nothing resolves the name
    again, so the answer that was checked is the answer that is used."""
    reason, host = _shape_refusal(url)
    if reason is not None:
        return reason, host, []
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        addresses = _resolve(host)
    if not addresses:
        return (f"{host} does not resolve" if require_resolution else None), host, []
    bad = [a for a in addresses if blocked_address(a)]
    if bad:
        return f"{host} resolves to an address Concord does not send to ({bad[0]})", host, []
    return None, host, addresses


def refusal(url: str, *, require_resolution: bool = False) -> str | None:
    """Why ``url`` may not receive webhooks, or None if it may.

    ``require_resolution`` is set at delivery: a name that does not resolve
    then cannot be sent to, and every address it resolves to must be allowed."""
    return _checked(url, require_resolution=require_resolution)[0]


def pinned_target(url: str) -> tuple[str | None, dict[str, object]]:
    """(refusal, request) for delivery: resolve once, check every address, and
    return the request to send **to an address from that same, checked
    answer**.

    Re-resolving at connect time would let a name answer differently the
    second time (DNS rebinding). The URL's host is replaced by the pinned IP;
    the original name travels in the ``Host`` header and as the TLS SNI name,
    so certificate verification still checks the name the user configured."""
    reason, host, addresses = _checked(url, require_resolution=True)
    if reason is not None or not addresses:
        return reason or f"{host} does not resolve", {}
    address = addresses[0]
    parts = urlsplit(url.strip())
    netloc_ip = f"[{address}]" if ":" in address else address
    if parts.port:
        netloc_ip = f"{netloc_ip}:{parts.port}"
    pinned = parts._replace(netloc=netloc_ip).geturl()
    host_header = f"[{host}]" if ":" in host else host  # an IPv6 literal (RFC 3986)
    if parts.port:
        host_header = f"{host_header}:{parts.port}"
    extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
    return None, {"url": pinned, "headers": {"Host": host_header}, "extensions": extensions}
