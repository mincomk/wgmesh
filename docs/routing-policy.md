# Routing policy, the exit peer and forwarding

This is the M1 half of the blueprint: §6 (AllowedIPs and the routing policy) and §6.6
(forwarding) wired into configuration, validation and the kernel. The pure decisions live in
`wgmesh-core::route`; this document is about how they reach a machine.

## Two paths, never one

The requirement reads like one sentence and is really two:

> give one peer `AllowedIPs = 0.0.0.0/0` so it can forward, and put only the bands you choose
> into the kernel routing table — or leave the table alone entirely.

AllowedIPs is WireGuard's **cryptokey routing** table. The kernel routing table is the
kernel's. Turning the first on says nothing about the second, and that is the whole point:

| | decided by | where it lands |
|---|---|---|
| AllowedIPs | `[peers] allowed_ips`, `[peers] exit_peer` | the WireGuard device, per peer |
| Routes | `[route] prefixes`, `[route] table` | the kernel routing table |

`AllowedIPs = 0.0.0.0/0` therefore never puts a default route in the kernel table. To send
everything through a gateway, name it: `exit_peer = "gw"` gives **that one peer** the
catch-all and leaves every other peer on its own `/32`.

Two peers may not both carry a catch-all. The kernel does not reject the overlap —
`wg_allowedips_insert_v4` only ever returns `-EINVAL` or `-ENOMEM` — it keeps whichever
insertion came last, silently. So the policy refuses the combination instead of letting
insertion order decide: `allowed_ips = "any"` with more than one peer is an error.

## Configuration

```toml
[peers]
allowed_ips = "peer"     # peer | any
exit_peer   = ""         # the one peer that also carries 0.0.0.0/0 and ::/0

[route]
table    = "main"        # main | <number> | off   ("auto" is only ever main)
prefixes = "auto"        # auto | none | ["10.77.0.0/16", "192.168.5.0/24"]
metric   = 0             # 0 means "no metric"
address  = "auto"        # auto | none

[forwarding]
enabled  = false
sysctl   = true          # may wgmesh set (and restore) the forwarding tunables
firewall = "off"         # off | manage
```

`prefixes = ["10.77.0.0/16", "192.168.5.0/24"]` is the "only the bands I chose" answer:
the network CIDR and whatever peers advertise stay out of the kernel table.

Refused, with the reason:

| what | why |
|---|---|
| a default route in `prefixes` | the catch-all is an AllowedIPs decision, not a kernel route |
| `prefixes = [..]` with `table = "off"` | "install no route" and "install this route" contradict |
| `allowed_ips = "any"` with more than one peer | the kernel resolves the overlap by insertion order |
| `exit_peer` naming a peer that does not exist | it would leave the catch-all unprogrammed |

## Ownership: the marker

Every route this package installs carries `proto 250` as its `proto`. iproute2's
`etc/iproute2/rt_protos` assigns names up to 192 (`eigrp`), so 250 is unassigned.

Ownership is a marker rather than a convention:

- `installed()` asks the kernel for `table <t> proto 250` and nothing else, so a route the
  host installed in the same table is invisible to us;
- `wgmesh routes plan` compares against exactly that set;
- `wgmesh routes reset` deletes exactly what that query returned — never by table, never by
  prefix alone.

The state file's `routes` array is a memory, not the truth. When the kernel cannot be asked
(no `iproute2`, no privileges) `routes plan` falls back to it and says so on stderr.

## Forwarding

`[forwarding] enabled = true` means this device is a gateway. Two switches decide what
wgmesh does about it, and each one changes only its own half:

- `sysctl = true` — wgmesh reads `net.ipv4.ip_forward` and
  `net.ipv6.conf.all.forwarding`, sets what is off, remembers what was there and puts it
  back when it stops. `sysctl = false` means wgmesh does not touch a tunable: it does not
  even read one.
- `firewall = "off"` (the default) — wgmesh does not touch the firewall at all.
  `firewall = "manage"` creates exactly one table, `inet wgmesh`, containing an accept-policy
  forward chain and `iifname`/`oifname` accept rules for the tunnel and the trusted
  interfaces. `nft delete table inet wgmesh` removes every trace, and no rule of ours is ever
  added to a chain the host owns.

The other side of that bargain is worth stating: **a host chain that drops forwarded traffic
still wins**, because a verdict in one base chain does not exempt a packet from the next one.
Getting forwarding through such a host is the host's business — which is exactly why wgmesh
never edits the host's rules, and why `wgmesh doctor` says so.

## Commands

```
wgmesh peers        [--config PATH] [--state PATH] [--json]   # where the catch-all went
wgmesh routes plan  [--config PATH] [--state PATH] [--json]   # what would be added or removed
wgmesh routes reset [--config PATH] [--json]                  # delete what the marker owns
wgmesh doctor       [--config PATH] [--json]                  # what to do next
```

`routes plan` never prints a default route: the desired side comes from `prefixes`, and
`table = "off"` plans nothing and does not ask the kernel anything either.

## What is verified, and what is not

Verified by `cargo test --workspace` (77 tests):

- `core::route`'s ten tests, unchanged;
- the peer policy: the catch-all on exactly one peer, the rest on their own `/32`, `any`
  refused for more than one peer, an unknown `exit_peer` refused by name and by id;
- the route plan: the default route refused in v4 and v6, an explicit list with `table =
  "off"` refused, an explicit list reaching the kernel as exactly those bands, `table = "off"`
  installing nothing, a second pass changing nothing;
- the adapter's argv, through a recording command runner: the marker on every add and
  delete, `table = "off"` rendering no route command at all, a foreign `proto` and another
  device filtered out of what the kernel reports;
- forwarding: `sysctl = false` performing no read and no write, a changed tunable restored to
  the value the host held, `firewall = "manage"` issuing `nft` commands that name
  `inet wgmesh` and nothing else, and one delete undoing all of it.

Not verified here: this Computer has no `NET_ADMIN`, so no route was actually installed in a
kernel, and no nftables table was actually created. Those paths are exercised by argv and by
the NixOS VM test (`nix/tests/forwarding.nix`), which is where a real kernel answers.
