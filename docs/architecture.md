# TlsNet architecture

## Scope

TlsNet is a hub-and-spoke IPv4 overlay. Every node connects outbound to one cloud
relay. Peers do not establish public P2P sessions. The first release supports one
relay, one Linux subnet gateway, and multiple road-warrior clients.

The public transport can use standard QUIC or TLS 1.3 over TCP with a configurable
cover SNI. TCP uses multiple independent lanes. The overlay carries raw IP packets;
it is not an HTTP or SOCKS proxy.

## Camouflage admission

Both public transports authenticate before exposing a TLSNet protocol response.
All admission tokens are short-lived HMAC values derived from the configured password
with Argon2id and domain-separated HKDF keys.

For TCP, the token occupies the TLS ClientHello random field. A matching SNI and token
select the local TLS 1.3 handler; any other syntactically valid ClientHello is relayed
byte-for-byte to the configured TCP cover target.

quic-go deliberately generates the client's Initial destination connection ID in an
internal function, so its public connection-ID generator cannot embed an admission
token there. TlsNet avoids a permanent quic-go fork: immediately before dialing, the
client sends one 1200-byte QUIC-v1-shaped Initial probe whose destination connection
ID contains the token. The relay temporarily admits that UDP endpoint, then passes
the following packets unchanged to standard quic-go. Unknown UDP endpoints are
forwarded through bounded NAT mappings to the configured UDP cover target.

This is a TLSNet camouflage design, not wire compatibility with Xray REALITY or
Hysteria.

## Components

### Relay

The Linux relay terminates TLS, authenticates nodes, assigns overlay addresses, and
forwards IPv4 packets by longest-prefix match. It owns the overlay prefix and keeps a
server-authorized mapping from node identity to advertised subnets.

### Linux gateway

The home gateway creates a TUN interface, maintains the TLS lanes, and advertises an
authorized LAN prefix such as `192.168.3.0/24`. The default deployment uses source NAT
on the gateway so the home router does not need a return route.

### Desktop client

Linux uses `/dev/net/tun`. Windows will use Wintun. Both clients receive their overlay
address and split routes from the relay before enabling their TUN adapter.

### Android client

The Android app uses Kotlin for lifecycle/UI and Android `VpnService` for the virtual
interface. The transport and packet core remains Go and is packaged as an AAR. The
app protects public transport sockets from VPN recursion and installs only the routes
pushed by the relay. Android is an access client in the first release and does not
advertise its local Wi-Fi network.

Only one Android VPN service can be active per user profile. TlsNet therefore cannot
run at the same time as another app using Android VPN/TUN mode.

## Session establishment

1. The client establishes a protected TLS control connection.
2. Client and relay authenticate a transcript bound to the TLS certificate.
3. The relay returns the assigned overlay address, MTU, permitted routes, session ID,
   and data-lane policy.
4. The client creates/configures its TUN interface.
5. Two to four TLS data lanes join the authenticated session.
6. Data frames carry sequence numbers so the receiver can perform bounded reordering.

The two-phase process is required because Android must know its address and routes
before calling `VpnService.Builder.establish()`.

## Routing and authorization

- The relay validates the source address of every overlay packet.
- Virtual addresses are assigned by the relay, not chosen by clients.
- Advertised LAN prefixes are approved in relay configuration per node identity.
- Longest-prefix matching selects either a node address or an advertised subnet.
- Broadcast, multicast, overlapping subnets, and arbitrary client route advertisement
  are rejected in the first release.

## Performance policy

- Wi-Fi and wired links default to four TLS/TCP lanes.
- Android cellular links default to two lanes to limit radio wakeups and battery use.
- Packet scheduling uses lane health and pending bytes rather than round-robin only.
- Reordering has a strict time and frame bound; a failed lane cannot block the session.
- MTU starts conservatively and will be configurable per node.

## Migration

Development uses `10.91.0.0/24` and TCP port `18444`, leaving the current EasyTier and
TlsTun deployment untouched. EasyTier is removed only after Linux, Windows, Android,
and home-subnet traffic pass connectivity, failover, and sustained-load tests.
