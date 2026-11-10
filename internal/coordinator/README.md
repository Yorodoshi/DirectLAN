# DirectLAN coordinator API

The coordinator stores public group membership and short-lived ICE signaling. It does not handle tunnel packets, private device keys, WireGuard session keys, or relay traffic. All non-health requests must use TLS in production and must be signed with the device's local Ed25519 identity key.

## Authentication

Send these headers on every `/v1` request:

| Header | Value |
| --- | --- |
| `X-DirectLAN-Key` | Ed25519 public key, unpadded base64url |
| `X-DirectLAN-Timestamp` | Unix time in whole seconds |
| `X-DirectLAN-Nonce` | 16–32 cryptographically random bytes, unpadded base64url; never reuse |
| `X-DirectLAN-Signature` | Ed25519 signature, unpadded base64url |

Sign the UTF-8 string below, with no final newline:

```text
METHOD\nRequestURI\ntimestamp\nnonce\nhex(SHA256(raw_body))
```

`RequestURI` includes the raw path and query string. The body hash is the lowercase hexadecimal SHA-256 digest of the exact bytes sent. Empty bodies are hashed as empty bytes. The coordinator allows ±60 seconds of clock skew, rejects reused nonces, and durably records nonces for modifying requests. Device IDs are the first 32 lowercase hexadecimal characters of `SHA256(Ed25519 public key)`; the full 64-character digest is the fingerprint shown to the owner for out-of-band confirmation. Device IDs alone are never accepted as proof of identity.

`public_key` in membership requests is a separate 32-byte WireGuard X25519 public key encoded with standard padded base64. The coordinator never asks for either private key.

## Endpoints

All times are RFC 3339 UTC. Unknown JSON fields and request bodies over 64 KiB are rejected.

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/register` | `{"device_name":"My PC"}` | `{"device_id","identity_public_key","fingerprint","device_name","registered_at"}`; signed proof of possession, idempotent |
| `POST /v1/groups` | `{"name":"Friends","network_cidr":"10.42.17.0/24","public_key":"<WG key>","overlay_ip":"10.42.17.1","device_name":"Owner"}` | Group snapshot, `201` |
| `POST /v1/groups/{network_id}/invitations` | Empty body or `{}`; owner only | `{"invitation":"<opaque>","network_id":"...","expires_at":"..."}`, `201` |
| `POST /v1/join` | `{"invitation":"...","public_key":"<WG key>","device_name":"Peer"}` | `{"pending_id":"...","network_id":"...","network_cidr":"...","owner_identity_public_key":"...","owner_fingerprint":"...","expires_at":"..."}`, `202` |
| `GET /v1/groups/{network_id}/pending` | Owner only | `{"pending":[{"pending_id","device_id","identity_public_key","fingerprint","public_key","device_name","expires_at"}]}` |
| `POST /v1/groups/{network_id}/pending/{pending_id}/approve` | `{"fingerprint":"<full 64 hex chars>","overlay_ip":"10.42.17.2"}`; owner only | Updated group snapshot |
| `DELETE /v1/groups/{network_id}/members/{device_id}` | Owner only | Updated group snapshot |
| `GET /v1/groups/{network_id}` | Member only | Group snapshot |
| `GET /v1/groups/{network_id}/heartbeat` | Member only | `{"network_id","revision","server_time"}` |
| `POST /v1/groups/{network_id}/signals` | See below | `{"seq":1}`, `201` |
| `GET /v1/groups/{network_id}/signals?after=0&after_revision=1&wait=25` | Member only; `wait` 0–25 seconds | Revision, members, signals addressed to caller |
| `GET /healthz` | No signature | `{"status":"ok"}` |

Group snapshots are `{"network_id","name","network_cidr","revision","owner_device_id","members":[...]}`. Each member has `device_id`, `identity_public_key`, `public_key`, `overlay_ip`, `device_name`, and `joined_at`. Registration stores a public identity record; successful create and join requests also register their signed identities. The owner selects a private IPv4 pool after client-side route checks and supplies each approved member's unique host IP. The coordinator enforces membership, private `/16`–`/28` pool syntax, and address uniqueness; it cannot see each computer's local routes.

An invitation is valid for ten minutes and is consumed by the first successful join request. The owner must check the joining identity fingerprint through an independent channel before approving. A pending request expires ten minutes after joining. Groups contain at most ten approved devices. Every approval or revocation increments `revision`. Clients must ignore older revisions and drop revoked peers promptly; they must stop existing authorizations after fifteen minutes without coordinator contact.

## ICE signaling

`POST /signals` accepts only typed ICE fields:

```json
{
  "to_device_id": "<member device ID>",
  "ice_ufrag": "abcd1234",
  "ice_pwd": "abcdefghijklmnopqrstuvwxyz",
  "candidates": ["candidate:1 1 udp 1234 192.0.2.1 12345 typ host"],
  "generation": 1,
  "expires_at": "2026-11-03T19:00:00Z"
}
```

`expires_at` must be in the future and no more than two minutes away. There may be at most 32 candidates of 1024 characters each and 8 KiB in total. The coordinator rejects payload fields, stores at most 64 unexpired signals per group, and exposes signals only to the addressed member. The receiver uses `seq` as its next `after` cursor and ignores expired candidates or old generations. A `GET /signals` response always includes the current membership revision and member list. A client waiting up to 25 seconds can therefore learn revocations within the specified 30-second window, subject to connectivity and scheduling. The coordinator cannot force a disconnected client to close a tunnel; the client's 15-minute authorization timeout is mandatory.

## Errors and operation

Errors have `{"code":"SOME_CODE","message":"human-readable message"}` with an appropriate HTTP status. Examples include `AUTH_INVALID`, `CLOCK_SKEW`, `REPLAY`, `INVITATION_EXPIRED`, `FINGERPRINT_MISMATCH`, `GROUP_FULL`, and `NOT_MEMBER`. Retrying a modifying request requires a fresh nonce and signature; joining with a consumed invitation requires a new invitation. Clients should use a current snapshot after ambiguous network failures.

Run in production with `-tls-cert`, `-tls-key`, `-state`, and `-listen`. The certificate must be trusted and checked by clients. For local tests only, `-dev-http-loopback -listen 127.0.0.1:8443` allows plain HTTP. Keep the state file on a protected volume. Only one process should use a state file. Configure a reverse proxy or firewall for external admission and capacity controls as needed; the built-in limiter permits ten requests per second per source IP with burst 100. This implementation caps one coordinator at 128 groups, 4096 registered identities, and 32 MiB of persisted metadata.
