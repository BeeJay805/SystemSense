# Passive configured-DNS route observation

The `network.connectivity` collector now asks Windows which **local IPv4 route**
it would select for at most two IPv4 DNS server addresses already returned by the
IP-enabled adapter configuration source. No model, case text, API caller, or URL
can supply a destination to this collector. It neither sends a packet nor
changes a route. This is a path-selection observation, **not** DNS resolution,
server reachability, application routing, or a diagnosis.

The query uses the documented `GetBestRoute(destination, source=0)` IP Helper API,
not a metric sort over WMI rows. The returned route contains the selected
interface index, route prefix, next hop, and metric. A configured DNS server may
appear on multiple adapters; the evidence retains all observed configuring
interface indices rather than assigning it to the first adapter. The native
query start and observation times are separate from the other connectivity
source times and final snapshot capture. Unavailable/denied/error results retain
coverage without a route. More than two distinct configured destinations, or
rows trimmed from the 4 KiB model preview, increment the omission count and
make the preview partial; the complete bounded detail remains local. If adapter
or DNS-list coverage is incomplete, the aggregate route stage is partial even
when each queried destination has a valid selected route. Query failures and
permission denials remain explicit on their individual rows.

`dns_route_schema_version=1` identifies snapshots with this collection stage.
Older snapshots parse with `None`, which means **not collected**, not “no DNS
configured.” For new snapshots, no configured IPv4 DNS is distinguished from
incomplete or denied adapter enumeration. The broader `network.configuration`
snapshot also exposes lower-bound omission counts when its WMI route or adapter
scan hits a cap; absence from a capped list is not proof of absence on Windows.

The collector's host readback on the development machine returned a selected
route that contained an observed configured DNS destination and had a nonzero
interface index. Fake-backed tests cover byte order, 56-byte native struct
layout, `source=0`, cross-adapter selection, denied/invalid results, timestamps,
and preview omission. That host readback is not an independent network or
repair oracle.

API sources: [GetBestRoute](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestroute),
[MIB_IPFORWARDROW](https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow).
