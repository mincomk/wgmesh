# Signed requests, approval, revocation and the audit log

This is the M2 security surface: what a device must prove to call the
coordinator, what the coordinator stores, what revocation does to a running
node, and how the coordinator's own identity is pinned.

The one property everything else serves: **the server holds no shared secret.**
It knows public keys and hashes. A dump of its database yields no credential and
no traffic key, and a captured request cannot be replayed.

## The request

```
Authorization: WGMESH <device_id> <unix_ts> <nonce_b64> <sig_b64>

sig = Ed25519(device_key,
        "WGMESHv1\n" + method + "\n" + path + "\n" +
        sha256_hex(body) + "\n" + ts + "\n" + base64(nonce))
```

The canonical string lives in `wgmesh-proto::signed::canonical` and both sides
call it, so there is one definition and no chance of the two drifting. The nonce
is 16 random bytes; the timestamp is a signed 64-bit second count.

Verification is five steps, in this order, and each failure names itself so a
log says which one it was:

| # | Step | Failure |
|---|---|---|
| 1 | the device id names an enrolled device | `unknown_identity` |
| 2 | that device is `active` | `identity_not_active` |
| 3 | `abs(now - ts) <= 60` | `clock_skew` |
| 4 | the nonce has not been seen in the last 120 seconds | `nonce_reused` |
| 5 | the signature verifies against the device's stored public key | `bad_signature` |

The nonce cache is the only server-side state this scheme needs. It holds
16-byte nonces and the second they arrived, prunes entries older than the
window on every insert, and dies with the process — which is correct, because
the window is shorter than any restart matters.

`wgmesh-secrets` owns the signing operations; `SecretStore::sign` is why a
private key never leaves the node, and `wgmesh-secrets::verify` is what the
coordinator calls so it never needs a signing library of its own.

## Enrollment, approval, revocation

A join token is one use, stored as a SHA-256 hash, and consumed in a single
`UPDATE ... RETURNING` statement, so two devices racing one token cannot both
win. Failure to redeem does not distinguish "unknown" from "expired": an
attacker learns nothing from the difference.

A device that enrolls against a token with `auto_approve = false` is inserted
`pending` and **does not appear in any peer list**. That is the cheapest safety
net in the design: a leaked token produces a device that can do nothing until an
operator approves it. `auto_approve = true` inserts it `active`.

**The peer list is the ACL.** `/v1/config` returns exactly the devices of the
network whose state is `active`, minus the caller, together with their tunnel
keys as the keyset. A device that is `pending` or `revoked` is simply absent.
Revocation therefore needs no session teardown: the next configuration sync
omits the peer, the agent's `core::diff` turns the omission into a
`Change::Remove`, and the adapter removes the peer entry — at which point the
kernel's cryptokey routing drops every packet from or to the addresses that peer
used to own, because no peer claims them any more. WireGuard has no session
cancellation, so the peer table *is* the revocation mechanism.

`FakeWireGuard` in `wgmesh-wireguard::testing` models exactly that, and
`crates/wgmesh-wireguard/tests/revocation_drops_packets.rs` walks the whole path:
enroll, sync, program, revoke at the coordinator, sync again, apply the diff,
and assert that the revoked peer's address no longer routes.

## The coordinator's identity

Enrollment records the coordinator's TLS SubjectPublicKeyInfo hash in the node's
configuration, and every request afterwards compares the certificate the server
presents against it. Pinning the *key* rather than the certificate is what lets
an ACME renewal keep working: a re-issued certificate over the same key keeps
the pin, and a new key does not.

`wgmesh trust show` prints the pin, `wgmesh trust rotate --from-cert <path>`
re-pins to a certificate the operator holds, and `wgmesh trust pin <path>`
prints what a certificate would produce without touching any configuration.
The rotation rewrites that one line of the agent configuration and leaves the
rest of the file alone. Until it runs, `TrustStore::ensure` refuses a
certificate the pin does not name, and that refusal is tested.

The SPKI is extracted from the DER by a small reader in `wgmesh-client::der`
rather than by a certificate dependency, and a certificate may be handed over as
PEM or as raw DER.

## The audit log

`audit_log` records `join`, `approve`, `revoke` and `rotate`, each with the actor
that caused it — the device's own id for `join` and `rotate`, the operator for
`approve` and `revoke` — a timestamp, the affected device row, and a detail
string carrying the state transition. `GET /v1/audit` reads it back behind the
admin credential.

## The admin credential

The operator's bootstrap credential is supplied in `WGMESH_ADMIN_TOKEN` when
`wgmeshd` starts. It is not written to the database, so the "no shared secret
stored" property covers the administrative surface too; only its hash exists,
and only in the process.

## What is verified where

`cargo test -p wgmesh-coordinator` covers rejection without a header, with a
wrong signature, with a replayed nonce inside the window, with a timestamp more
than 60 seconds from now, from a `pending` device and from a `revoked` device;
that a nonce is accepted again after the window; that `auto_approve = false`
stays `pending` and absent from the peer list; that approval puts a device in;
that revocation removes it from the peer list *and* the keyset; that the schema
stores hashes and public keys only; and that join, approve, revoke and rotate
appear in the audit log with their actor.

`cargo test -p wgmesh-client` and `cargo test -p wgmesh-cli` cover the pin: two
real certificates, the SPKI hash checked against an independently computed
value, PEM and DER agreeing, rotation moving the pin and the old value then
refusing the new certificate.

`cargo test -p wgmesh-wireguard` covers the adapter: a peer removed from the
table stops owning its addresses, and the end-to-end test above ties the
coordinator's revocation to that removal.

## Not verified here

* The live TLS capture of the coordinator's certificate. `trust rotate` takes the
  certificate explicitly because the HTTPS client adapter that would fetch it is
  not in this change; the pinning logic it will call is the tested part.
* The kernel adapter itself. `FakeWireGuard` is a model of cryptokey routing, and
  the netlink adapter that programs the real kernel is a separate crate; this
  environment has no `CAP_NET_ADMIN`, so the model is what can be run here.
* Rate limiting, SSE and the metrics surface, which are a separate step. The
  schema and the audit log they will report into are in place.
