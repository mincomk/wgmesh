# End-to-end test: one router (coordinator + relay) and two agent nodes.
#
# This is the test that has to run on a real kernel -- the VMs use the kernel's
# WireGuard, so the traversal state machine, the relay, the netlink adapter and
# the routing policy are all exercised for real. It cannot run in a sandbox
# without /dev/kvm; see docs/nixos-modules.md.
#
# The one part written from the specification rather than from a run is the
# coordinator's minting subcommands (`wgmeshd bootstrap`, `wgmeshd token`),
# since they cannot be run outside such a machine.
{ self }:
{
  pkgs,
  lib,
  ...
}:

let
  wgmesh = self.packages.${pkgs.stdenv.hostPlatform.system}.wgmesh;

  # A self-signed certificate for the coordinator's reverse proxy, plus the SPKI
  # pin the nodes are configured with -- the same value `wgmesh pin <url>` would
  # print for this certificate. Computing it in the store keeps the pin and the
  # certificate from drifting apart.
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

  # Reading a derivation's file at evaluation time; the pin is a build product,
  # not something to copy around by hand.
  spki = lib.removeSuffix "\n" (builtins.readFile "${cert}/spki");

  # Shared configuration of the two agent nodes. The join token is written into
  # place by the test script and reaches the unit as a systemd credential, so the
  # unit is deliberately not started at boot.
  agentNode =
    { lib, ... }:
    {
      imports = [ self.nixosModules.agent ];

      # The test script runs `wgmesh` from the node's own shell, so the package
      # has to be on PATH; the unit's ExecStart uses the store path directly.
      environment.systemPackages = [ wgmesh ] ++ (with pkgs; [
        jq
        wireguard-tools
      ]);

      services.wgmesh.agent = {
        enable = true;
        package = wgmesh;
        openFirewall = true;
        # Written by the script just before it starts the unit; the module hands
        # it to the agent as the `enrollment-token` credential.
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
          # Tighten the observation window so the test does not sit still.
          traversal = {
            punch_delay_secs = 1;
            punch_window_secs = 3;
            keepalive_secs = 5;
          };
        };
      };

      systemd.services.wgmesh-agent.wantedBy = lib.mkForce [ ];
    };
in
{
  name = "wgmesh-e2e";

  nodes = {
    router = {
      imports = [
        self.nixosModules.coordinator
        self.nixosModules.relay
      ];

      # `wgmeshd` is driven from this shell (`bootstrap`, `token create`), and
      # the relay's own token is minted into the same file the agent uses.
      environment.systemPackages = [ wgmesh ] ++ (with pkgs; [ jq ]);

      services.wgmesh.coordinator = {
        enable = true;
        package = wgmesh;
        settings.policy.default_auto_approve = true;
      };

      services.wgmesh.relay = {
        enable = true;
        package = wgmesh;
        openFirewall = true;
        enrollmentTokenFile = "/etc/wgmesh/token";
        settings = {
          relay.port_range = [
            51820
            51999
          ];
          # The relay's `[coordinator]` table has no `network`: it takes part in
          # no network of its own, it serves the ones the coordinator hands it.
          coordinator = {
            url = "https://router/";
            spki_sha256 = spki;
          };
        };
      };

      # TLS for the coordinator: it speaks plain HTTP on the loopback address and
      # is published through the proxy, which is the deployment the module
      # documentation describes.
      services.caddy = {
        enable = true;
        virtualHosts."router".extraConfig = ''
          tls ${cert}/cert.pem ${cert}/key.pem
          reverse_proxy 127.0.0.1:8080
        '';
      };
      networking.firewall.allowedTCPPorts = [ 443 ];

      systemd.services.wgmesh-relayd.wantedBy = lib.mkForce [ ];
    };

    nodeA = agentNode;
    nodeB = agentNode;
  };

  testScript = ''
    start_all()

    router.wait_for_unit("wgmeshd.service")
    router.wait_for_open_port(8080)
    router.wait_for_unit("caddy.service")
    router.wait_for_open_port(443)

    # The first network and an admin credential to mint tokens with.
    router.succeed("wgmeshd bootstrap --network default")

    # The relay enrolls like any other member, so its token is minted first.
    def enroll(node, name):
        token = router.succeed(f"wgmeshd token create --network default --name {name}").strip()
        node.succeed("mkdir -p /etc/wgmesh")
        node.succeed(f"printf '%s' '{token}' > /etc/wgmesh/token")
        node.succeed("chmod 0400 /etc/wgmesh/token")

    enroll(router, "relay-1")
    router.succeed("systemctl start wgmesh-relayd")
    router.wait_for_unit("wgmesh-relayd.service")

    for name, node in (("nodeA", nodeA), ("nodeB", nodeB)):
        enroll(node, name)
        node.succeed("systemctl start wgmesh-agent")
        node.wait_for_unit("wgmesh-agent.service")

    # Every node must see the other one.
    nodeA.wait_until_succeeds("wgmesh status --json | jq -e '.peers | length >= 1'")
    nodeB.wait_until_succeeds("wgmesh status --json | jq -e '.peers | length >= 1'")

    # The tunnel works: a ping through the relay path is enough to prove the
    # overlay is up.
    addrB = nodeB.succeed("ip -4 -o addr show dev wg0 | awk '{print $4}' | cut -d/ -f1").strip()
    nodeA.wait_until_succeeds(f"ping -c1 -W2 {addrB}")

    # And then the two nodes stop using the relay: the direct path is promoted.
    nodeA.wait_until_succeeds(
        "wgmesh status --json | jq -e '.peers[0].path == \"direct\"'", timeout=180
    )
    nodeB.wait_until_succeeds(
        "wgmesh status --json | jq -e '.peers[0].path == \"direct\"'", timeout=180
    )

    # Ping again on the direct path, so a promotion that silently broke the
    # data plane fails the test.
    nodeA.succeed(f"ping -c1 -W2 {addrB}")
  '';
}
