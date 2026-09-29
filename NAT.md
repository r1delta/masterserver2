# NAT traversal support

Implemented in `nat.go`; the game side lives in `r1delta/p2p/` (see its
README for the full design).

## What changed for servers

`POST /heartbeat` accepts two optional objects:

```json
"transports": {
  "eos":       {"puid": "0002...32 hex"},
  "iroh":      {"id": "64 hex", "relay": "https://...", "addrs": ["1.2.3.4:5678"]},
  "tailcat":   {"addr": "tc..."},
  "tailscale": {"ips": ["100.101.102.103"]},
  "turn":      {"relay": "104.30.1.2:49160"}
},
"nat": {"want_turn": true, "lan": ["192.168.1.5:37015"], "upnp": "upnp", "upnp_external": "1.2.3.4:37015"}
```

Everything is sanitised (`sanitizeTransports`, `sanitizeLAN`); malformed
entries are dropped. A heartbeat with a `nat` object marks the server `p2p`
capable. The response body is now JSON (older game builds ignore it):

```json
{"rendezvous": "203.0.113.10:37999", "token": "32 hex", "public_ip": "...",
 "reach": {"direct": false, "punch": true, "turn": false}, "validated": true,
 "turn": {"urls": ["turn:turn.cloudflare.com:3478?transport=udp"], "username": "...", "credential": "...", "expires": 0}}
```

`turn` is only present when the server asked for it, validation has run and
the server was **not** reachable directly, so TURN bandwidth is only spent on
servers that need it.

Validation (`PerformValidation`) now tries, in order: direct UDP (as before),
the connect challenge sent from the rendezvous socket to the server's
registered NAT mapping, and the same through its advertised TURN relay. The
server is listed if any path answers; `reach` records which ones did.

## New for clients

* `/servers` entries gain `transports`, `reach` and `p2p`.
* `POST /nat/connect {"server": "ip:port"}` returns a punch `ticket`, the
  `rendezvous` address, `server_mapped`, the server's `lan` addresses (only
  when the client shares the server's public IP), `transports`, `reach` and
  `p2p`. It also pushes a permission-only punch request so a TURN-relayed
  server accepts the client right away.

## UDP rendezvous

A UDP socket (default `:37999`) handles the `R1NX` control packets: server
registrations (keeps the server's NAT mapping known and open), client ticket
registrations (a ticket is only accepted from the public IP that requested
it) and punch requests/acks towards servers. Packet formats are documented in
`r1delta/p2p/README.md`.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `RENDEZVOUS_LISTEN` | `:37999` | UDP listen address, or `off` |
| `RENDEZVOUS_PUBLIC_ADDR` | discovered public IP + listen port | Address advertised to servers/clients. Must be the origin, not a Cloudflare-proxied name. |
| `CF_TURN_KEY_ID`, `CF_TURN_API_TOKEN` | unset | Cloudflare Realtime TURN key; TURN is disabled without them |
| `CF_TURN_TTL` | `43200` | Credential lifetime in seconds (cached per server, re-minted with < 1/4 left) |
| `CF_TURN_API_URL` | Cloudflare `generate-ice-servers` URL | Override (format string taking the key id), e.g. for a self-hosted TURN credential service |

The rendezvous port must be reachable over UDP from the internet (open it in
the firewall next to the HTTP port).

## Tests

`go test ./...` runs `nat_test.go`, including a UDP end-to-end test with a
fake NAT'd game server (registration, validation through the mapping, client
ticket flow, punch request delivery, spoofed-IP rejection).
