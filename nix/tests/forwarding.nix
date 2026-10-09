# Forwarding and routing-policy test.
#
# The shape is the one the routing policy exists for: a gateway node (`gw`)
# forwards for the mesh, and behind it sits a host (`hidden`) that is not a mesh
# member, on a network of its own. A client (`nodeA`) sends everything through
# the gateway -- its AllowedIPs for `gw` are 0.0.0.0/0 -- while the kernel's
# routing table holds only the prefixes it chose, and never a default route.
#
# `nodeOff` is the other end of the policy: a node that manages its own routing
# (`route.table = "off"`) must have wgmesh install no routes at all, while still
# owning its interface and address.
#
# As in e2e.nix, the coordinator's minting subcommands follow the design
# document's CLI surface rather than a run: these tests need a machine with KVM.
{ self }:
{
  pkgs,
  lib,
  ...
}:

let
  wgmesh = self.packages.${pkgs.stdenv.hostPlatform.system}.wgmesh;

  cert = pkgs.runCommand "wgmesh-test-cert" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout $out/key.pem -out $out/cert.pem \
      -subj "/CN=router" -addext "subjectAltName=DNS:router,IP:127.0.0.1,IP:10.0.0.1"
    openssl x509 -in $out/cert.pem -noout -pubkey \
      | openssl pkey -pubin -outform DER \
      | sha256sum | cut -d' ' -f1 > $out/spki
  '';

  spki = lib.removeSuffix "\n" (builtins.readFile "${cert}/spki");

  # The test driver gives the nodes of vlan N the subnet 192.168.N.0/24, so
  # `hidden` on its own vlan is reachable from `nodeA` only through `gw`.
  hiddenNetwork = "192.168.2.0/24";

  agentCommon = {
    enable = true;
    package = wgmesh;
    openFirewall = true;
    # Written by the test script and injected as the `enrollment-token`
    # credential before the unit is started.
    enrollmentTokenFile = "/etc/wgmesh/token";
    settings = {
      interface.listen_port = 51820;
      coordinator = {
        url = "https://router/";
        spki_sha256 = spki;
        network = "default";
      };
      enrollment.wait_for_approval = false;
      log.level = "debug";
      sync.interval_secs = 5;
    };
  };

  agentNode =
    extra:
    { lib, ... }:
    {
      imports = [ self.nixosModules.agent ];

      # The test script runs `wgmesh status --json` from the node's own shell.
      environment.systemPackages = [ wgmesh ] ++ (with pkgs; [
        jq
        wireguard-tools
      ]);

      services.wgmesh.agent = lib.recursiveUpdate agentCommon extra;

      systemd.services.wgmesh-agent.wantedBy = lib.mkForce [ ];

      virtualisation.vlans = [ 1 ];
    };
in
{
  name = "wgmesh-forwarding";

  nodes = {
    router = {
      imports = [ self.nixosModules.coordinator ];

      # `wgmeshd` is driven from this shell: the first network and every join
      # token are minted here.
      environment.systemPackages = [ wgmesh ] ++ (with pkgs; [ jq ]);

      services.wgmesh.coordinator = {
        enable = true;
        package = wgmesh;
        settings.policy.default_auto_approve = true;
      };

      services.caddy = {
        enable = true;
        virtualHosts."router".extraConfig = ''
          tls ${cert}/cert.pem ${cert}/key.pem
          reverse_proxy 127.0.0.1:8080
        '';
      };
      networking.firewall.allowedTCPPorts = [ 443 ];

      virtualisation.vlans = [ 1 ];
    };

    # The gateway: a mesh member that also routes for the network behind it.
    gw = {
      imports = [ self.nixosModules.agent ];

      # The script inspects this node from its shell: wgmesh, wg, nft, ip.
      environment.systemPackages = [ wgmesh ] ++ (with pkgs; [
        jq
        nftables
        wireguard-tools
      ]);

      services.wgmesh.agent = lib.recursiveUpdate agentCommon {
        settings.forwarding.enabled = true;
        forwarding = {
          enable = true;
          firewall = "manage";
          # The interface on the hidden host's segment.
          trustedInterfaces = [ "eth2" ];
        };
      };

      systemd.services.wgmesh-agent.wantedBy = lib.mkForce [ ];

      # forwarding.firewall = "manage" adds an nftables table, and nftables is
      # not on by default -- the module refuses to be a no-op.
      networking.nftables.enable = true;

      virtualisation.vlans = [
        1
        2
      ];
    };

    # A client that sends everything it does not know to the gateway.
    nodeA = agentNode {
      settings = {
        peers.exit_peer = "gw";
        route = {
          table = "main";
          prefixes = [ hiddenNetwork ];
        };
      };
    };

    # A client that does its own routing.
    nodeOff = agentNode {
      settings.route = {
        table = "off";
        address = "auto";
      };
    };

    # Not a mesh member: a host on the far side of the gateway.
    hidden = {
      virtualisation.vlans = [ 2 ];
    };
  };

  testScript = ''
    import ipaddress

    start_all()

    router.wait_for_unit("wgmeshd.service")
    router.wait_for_open_port(8080)
    router.wait_for_unit("caddy.service")


    def enroll(node, name):
        token = router.succeed(
            f"wgmeshd token create --network default --name {name}"
        ).strip()
        node.succeed("mkdir -p /etc/wgmesh")
        node.succeed(f"printf '%s' '{token}' > /etc/wgmesh/token")
        node.succeed("chmod 0400 /etc/wgmesh/token")


    for name, node in (("gw", gw), ("nodeA", nodeA), ("nodeOff", nodeOff)):
        enroll(node, name)
        node.succeed("systemctl start wgmesh-agent")
        node.wait_for_unit("wgmesh-agent.service")

    # Every node has to know every other one before any of this means anything.
    for node in (gw, nodeA, nodeOff):
        node.wait_until_succeeds("wgmesh status --json | jq -e '.peers | length >= 2'")

    # The gateway forwards: the module's sysctls are in place...
    with subtest("the gateway forwards and filters nothing in FORWARD"):
        # The module's sysctls are in place...
        assert gw.succeed("cat /proc/sys/net/ipv4/ip_forward").strip() == "1"
        assert gw.succeed("cat /proc/sys/net/ipv6/conf/all/forwarding").strip() == "1"
        # The module manages this table itself (forwarding.firewall = "manage").
        gw.succeed("nft list table inet wgmesh-forward")

    # ...and the catch-all is in exactly one place, the client's entry for the
    # gateway. The gateway does not hand 0.0.0.0/0 to anyone.
    with subtest("AllowedIPs: one peer carries the catch-all"):
        a_allowed = nodeA.succeed("wg show wg0 allowed-ips")
        catch_all = [l for l in a_allowed.splitlines() if "0.0.0.0/0" in l]
        assert len(catch_all) == 1, f"nodeA gave 0.0.0.0/0 to {len(catch_all)} peers:\n{a_allowed}"

        gw_allowed = gw.succeed("wg show wg0 allowed-ips")
        assert "0.0.0.0/0" not in gw_allowed, (
            f"the gateway hands out a catch-all of its own:\n{gw_allowed}"
        )

    # The kernel routing table holds the prefixes we chose and never a default
    # route -- this is the invariant the policy exists to keep.
    with subtest("the routing table has the chosen prefixes and no default"):
        routes = nodeA.succeed("ip route show proto wgmesh")
        assert hiddenNetwork in routes, f"{hiddenNetwork} missing from:\n{routes}"
        assert not any(l.startswith("default") for l in routes.splitlines()), routes
        assert not any(
            "default" in l and "wg0" in l for l in nodeA.succeed("ip route show").splitlines()
        ), "nodeA has a default route through the tunnel"

    with subtest("route.table = off installs no routes"):
        assert nodeOff.succeed("ip route show proto wgmesh").strip() == ""
        # The interface and its address are still ours.
        nodeOff.succeed("ip link show wg0")
        nodeOff.succeed("ip -4 addr show dev wg0")

    # The host behind the gateway is reachable over the tunnel. It needs a route
    # back into the mesh itself -- the gateway forwards, it does not masquerade.
    with subtest("a host behind the gateway is reachable"):
        gw_addr = gw.succeed(
            "ip -4 -o addr show | grep 192.168.2. | head -1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        assert gw_addr, "could not find the gateway's address on the hidden host's segment"

        tunnel_network = ipaddress.ip_network(
            nodeA.succeed("jq -r .tunnel_ip /var/lib/wgmesh/state.json").strip(),
            strict=False,
        )
        hidden.succeed(f"ip route add {tunnel_network} via {gw_addr}")

        hidden_addr = hidden.succeed(
            "ip -4 -o addr show | grep 192.168.2. | head -1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        nodeA.wait_until_succeeds(f"ping -c1 -W2 {hidden_addr}")
  '';
}
