# Rampart перед Minecraft Java

Rampart can proxy Minecraft Java Edition over TCP. It checks the bounded Java
handshake, forwards the original bytes unchanged, and then tunnels the
connection to one Paper backend. This is an early integration: it does not
replace an upstream DDoS scrubbing network.

## Build and configure

Build the edge binary with the Minecraft handler:

```sh
cargo build --release --features protocol-minecraft --bin rampart
```

Use one backend per edge node. For a Paper server on the same host, the sample
uses port `25566`; change it to the address reachable over your private network
or WireGuard tunnel.

```toml
whitelist = ["127.0.0.1", "::1"]

[bind]
address = "0.0.0.0"
port = 25565

[backend]
upstreams = ["10.20.0.5:25566"]

[protocol.minecraft]
enabled = true
max_frame_bytes = 8192
timeout_secs = 5
send_proxy_protocol = true

[pow]
enabled = false
```

PoW must stay disabled for Minecraft Java: the current PoW exchange is plain
text and is not part of the Minecraft protocol. Configure the edge firewall to
allow public TCP `25565`, and keep Prometheus `9090` and the Paper backend port
private.

## Handshake hygiene

Handshake и login-start идут открытым текстом, поэтому Rampart проверяет их до
подключения к Paper. Любое нарушение — тихое закрытие соединения без ответа.
Handler читает handshake и следующий за ним кадр (status request или login-start)
и пересылает оба на backend байт-в-байт.

Что отклоняется:

- пустой или длиннее 255 символов hostname; hostname не UTF-8;
- второй handshake, login-start до handshake, второй login-start;
- `next_state` не из `{1, 2, 3}` (3 — transfer, обрабатывается как login);
- неправдоподобный protocol id (меньше 4 или больше 65535, кроме снапшотов с битом 30);
- версия вне `min_protocol_version`/`max_protocol_version` или из `deny_protocol_versions`;
- ник длиной вне `1..=username_max_len` или с символами вне `username_charset`
  (по умолчанию `A-Za-z0-9_.-`, длина до 16);
- status request не равный пустому пакету `0x00`.

Размер кадра проверяется сразу после декодирования VarInt длины, до чтения тела:
handshake до `max_handshake_bytes` (2048), login-start до `max_login_start_bytes`
(5120), status request до `max_status_request_bytes` (64); общий потолок —
`max_frame_bytes`.

```toml
[protocol.minecraft]
min_protocol_version = 47
deny_protocol_versions = [340]
username_max_len = 16
username_charset = "standard"
```

Метрики (`/metrics`):

- `rampart_mc_handshake_total{result,reason}` — `result` это `accepted` или `rejected`;
  `reason` из закрытого набора: `ok`, `frame_length`, `frame_too_large`, `malformed`,
  `unexpected_packet`, `empty_hostname`, `oversized_hostname`, `bad_hostname`,
  `duplicate_handshake`, `login_before_handshake`, `duplicate_login_start`,
  `bad_next_state`, `implausible_version`, `version_below_min`, `version_above_max`,
  `version_denied`, `bad_username`, `bad_status_request`, `timeout`, `io`.
- `rampart_mc_protocol_version_total{version}` — имя релиза из встроенной таблицы
  (например `1.20.3-4`), всё остальное — `other`. Считается каждый разобранный handshake,
  включая отклонённые политикой (`min/max_protocol_version`, `deny_protocol_versions`).

Ограничения: второй login-start виден только если клиент прислал его сразу следом
за первым; после ответа сервера трафик шифруется и не разбирается.

## Preserve player IPs safely

When `send_proxy_protocol` is enabled, Rampart prepends a PROXY protocol v2 header
before the Minecraft handshake. On Paper, enable `proxies.proxy-protocol` in
`config/paper-global.yml`. Paper documents this option for HAProxy or similar
proxies: [global configuration](https://docs.papermc.io/paper/reference/global-configuration/).

The PROXY header is not authenticated. Put the edge-to-Paper connection on a
private network or WireGuard and firewall Paper's backend port to accept only
the trusted edge IPs. Never expose a PROXY-enabled Paper port to arbitrary
clients: they could forge the address in the header.

If Rampart runs in Docker, the container needs access to the configured backend
address. The included sample image builds `protocol-minecraft`; the sample
config keeps PROXY protocol disabled until Paper and the backend firewall are
configured together.

## DDoS boundary

Rampart can reject connections and apply local rate limits after packets reach
the edge host. It cannot keep a home uplink available when an attack saturates
that link. Put a Minecraft-aware DDoS proxy or a provider with game DDoS
filtering in front of the VDS, hide the home's public address, and carry
accepted traffic to the home server through a restricted tunnel. Two ordinary
VDS instances without upstream filtering do not provide that protection.

## Network layout and firewall

Use the VDS edge as the only public Minecraft endpoint. The provider should
send filtered TCP `25565` traffic to that edge; the edge then reaches Paper over
a private link (for example, WireGuard). Use addresses from your own VPN and
replace the example roles below with the actual interfaces and addresses.

| Service | Allowed source | Publicly reachable? |
| --- | --- | --- |
| VDS edge TCP `25565` | DDoS provider ranges, or the Internet only if the provider requires it | Yes, through the provider |
| Paper TCP `25566` | Edge VPN address only | No |
| Redis TCP `6379` | Manager and edge VPN addresses only | No |
| Manager API TCP `8080` | Admin VPN or explicitly allowed admin IPs | No |
| Prometheus TCP `9090` | Monitoring VPN / localhost | No |

Do not forward Paper, Redis, or management ports from the home router to the
Internet. On Proxmox, allow the Paper port only on the tunnel/private interface
and restrict it to the edge addresses. If Manager and Redis run on a VDS, bind
or firewall Redis to the private interface and let each edge reach it through
the VPN. Use the same protected Redis endpoint in Manager and every edge
configuration; do not publish Redis with a Docker `ports` mapping. Protect the
Manager API and monitoring UI with the admin VPN or firewall as well. A private
tunnel limits who can reach these services; it does not add DDoS scrubbing to
the public edge.

For a DDoS provider that sends PROXY protocol v2, enable inbound parsing only
for that provider's TCP source ranges:

```toml
[proxy_protocol]
ingress_enabled = true
# Replace these documentation ranges with the provider's actual ranges.
trusted_cidrs = ["198.51.100.0/24", "2001:db8:1234::/48"]
ingress_timeout_ms = 750
max_header_bytes = 512
```

Rampart rejects connections from unlisted peers when ingress mode is enabled,
and it applies per-IP limits and bans using the verified header source address.
Keep the allowlist current with the provider's published ranges. The header is
not cryptographically authenticated, so never trust arbitrary internet peers.
This MVP accepts PROXY v2 TCP4/TCP6 address headers without TLVs; confirm that
format with the provider before enabling ingress mode.
XDP operates on the network peer address and is not used to ban the claimed
player address on this path.

The Minecraft handler supports status and login handshake states and forwards
the connection as a TCP tunnel. It does not inspect encrypted login/game
packets or implement Velocity forwarding. Bedrock Edition uses UDP and is not
supported by this handler.
