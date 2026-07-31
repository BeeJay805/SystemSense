"""DNS server and proxy configuration without active resolution."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class DnsProxyObservation(FrozenModel):
    dns_servers: tuple[str, ...]
    proxy_enabled: bool
    proxy_server: str | None = Field(default=None, max_length=4096)


def collect_dns_proxy(
    observations: tuple[DnsProxyObservation, ...],
) -> DnsProxyObservation:
    if not observations:
        return DnsProxyObservation(
            dns_servers=(),
            proxy_enabled=False,
            proxy_server=None,
        )
    servers: list[str] = []
    proxy_enabled = False
    proxy_server: str | None = None
    for observation in observations[:64]:
        for server in observation.dns_servers:
            if server not in servers and len(servers) < 32:
                servers.append(server)
        if observation.proxy_enabled:
            proxy_enabled = True
            proxy_server = observation.proxy_server
    return DnsProxyObservation(
        dns_servers=tuple(servers),
        proxy_enabled=proxy_enabled,
        proxy_server=proxy_server,
    )
