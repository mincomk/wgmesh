# `wg-handshake.pcap` — a real WireGuard handshake

Captured on the Attacca Computer, 2026-10-09, with `tcpdump`:

```
sudo tcpdump -i lo -s0 -U -w wg-handshake.pcap \
  'udp port 51901 or udp port 51902 or udp port 51903 or udp port 51904'
```

while `wgcap` — a two-peer WireGuard handshake driven by **boringtun 0.7.1**, an independent
WireGuard implementation (Cloudflare's) — ran over loopback UDP. The capture therefore holds
genuine WireGuard datagrams: a real Noise_IKpsk2 handshake was performed by a real
implementation, and these are the bytes it put on the wire.

What the capture contains, in order:

| # | Direction | Type | Bytes |
|---|---|---|---|
| 1 | 51901 → 51902 | 1, initiation | 148 |
| 2 | 51902 → 51901 | 2, response | 92 |
| 3 | 51901 → 51902 | 4, transport (keepalive) | 32 |
| 4 | 51901 → 51902 | 4, transport (keepalive) | 32 |
| 5 | 51901 → 51902 | 4, transport (a 31-byte tunnel packet, padded) | 64 |
| 6 | 51903 → 51904 | 1, initiation | 148 |
| 7 | 51904 → 51903 | 3, cookie reply | 64 |

Datagrams 6 and 7 are a second, deliberately different exchange: the responder there was
configured to consider itself under load, so it answered an initiation whose `mac2` did not
verify with a **cookie reply** — the only way to observe a type 3 packet without one peer
already holding a cookie.

The two static public keys the peers used (WireGuard never puts them on the wire, so they are
recorded here from the run that produced the capture):

```
initiator  7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13
responder  0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20
```

`crates/wgmesh-relay/tests/wireguard_capture.rs` replays every datagram above through
`RelayTable::route_one_port` and checks the offsets against the capture's own bytes.

**What this capture is not:** it is not a kernel `wireguard` interface. The kernel path could
not be run on this Computer to produce it — see `docs/wgmesh-M3-routing-report.md` §7 — so no
kernel `wg` module and no `wg(8)` was involved. The bytes are WireGuard's, produced by an
implementation that interoperates with the kernel's; the relay's arithmetic is thus measured
against real traffic, but the kernel's own framing has still not been captured here.
