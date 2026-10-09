# Relay test: a coordinator, two relays and one node.
#
# The point of this test is the relay's operational surface: a node is assigned
# to a relay, the relay binds a slot for it inside its configured port range,
# and draining the relay moves the node to the other one without either side
# being restarted.
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

  # Both relays are configured identically, down to the port range, so a slot
  # number alone does not say which of them bound it.
  relayNode =
    { lib, ... }:
    {
      imports = [ self.nixosModules.relay ];

      environment.systemPackages = with pkgs; [ jq ];

      services.wgmesh.relay = {
        enable = true;
        package = wgmesh;
        openFirewall = true;
        settings = {
          relay.port_range = [
            51820
            51999
          ];
          coordinator = {
            url = "https://router/";
            spki_sha256 = spki;
            network = "default";
          };
          log.level = "debug";
        };
      };

      systemd.services.wgmesh-relayd.wantedBy = lib.mkForce [ ];
    };
in
{
  name = "wgmesh-relay";

  nodes = {
    router = {
      imports = [ self.nixosModules.coordinator ];

      environment.systemPackages = with pkgs; [ jq ];

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
    };

    relay1 = relayNode;
    relay2 = relayNode;

    nodeA = {
      imports = [ self.nixosModules.agent ];

      environment.systemPackages = with pkgs; [ jq ];

      services.wgmesh.agent = {
        enable = true;
        package = wgmesh;
        openFirewall = true;
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

      systemd.services.wgmesh-agent.wantedBy = lib.mkForce [ ];
    };
  };

  testScript = ''
    start_all()

    router.wait_for_unit("wgmeshd.service")
    router.wait_for_open_port(8080)
    router.wait_for_unit("caddy.service")

    # The first network, and an admin credential to mint tokens with.
    router.succeed("wgmeshd bootstrap --network default")


    def enroll(node, name):
        """Mint a join token for `node` and put it where the unit expects it."""
        token = router.succeed(
            f"wgmeshd token create --network default --name {name}"
        ).strip()
        node.succeed("mkdir -p /etc/wgmesh")
        node.succeed(f"printf '%s' '{token}' > /etc/wgmesh/token")
        node.succeed("chmod 0400 /etc/wgmesh/token")


    for name, node in (("relay1", relay1), ("relay2", relay2)):
        enroll(node, name)
        node.succeed("systemctl start wgmesh-relayd")
        node.wait_for_unit("wgmesh-relayd.service")

    enroll(nodeA, "nodeA")
    nodeA.succeed("systemctl start wgmesh-agent")
    nodeA.wait_for_unit("wgmesh-agent.service")

    # The node is assigned to one of the two relays...
    nodeA.wait_until_succeeds("jq -e '.relay.slot_port != null' /var/lib/wgmesh/state.json")
    slot = int(nodeA.succeed("jq -r .relay.slot_port /var/lib/wgmesh/state.json").strip())
    assert 51820 <= slot <= 51999, f"slot {slot} is outside the configured port range"


    def has_slot(node, port):
        """Does `node` have a socket bound on `port` (listening or not)?"""
        return node.execute(f"ss -lun | grep -qw {port}")[0] == 0


    # ...and the relay that was assigned to it binds the slot.
    with subtest("the assigned relay binds the slot"):
        retry(lambda: has_slot(relay1, slot) or has_slot(relay2, slot))

    if has_slot(relay1, slot):
        drained, drained_name = relay1, "relay1"
        other, other_name = relay2, "relay2"
    else:
        drained, drained_name = relay2, "relay2"
        other, other_name = relay1, "relay1"

    # Draining is a reload, not a restart: the relay keeps carrying the traffic
    # it already forwards, stops taking new assignments, and the coordinator
    # moves what it holds to the other relay.
    pid_before = drained.succeed("systemctl show -p MainPID --value wgmesh-relayd.service").strip()
    drained.succeed("systemctl reload wgmesh-relayd")
    drained.wait_for_unit("wgmesh-relayd.service")

    with subtest("draining moves the assignment to the other relay"):
        nodeA.wait_until_succeeds(
            f"test \"$(jq -r .relay.assigned /var/lib/wgmesh/state.json)\" = {other_name}",
            timeout=180,
        )

    new_slot = int(nodeA.succeed("jq -r .relay.slot_port /var/lib/wgmesh/state.json").strip())
    with subtest("the new relay carries the node's slot"):
        other.wait_until_succeeds(f"ss -lun | grep -qw {new_slot}")

    # And the drained relay was not restarted on the way out.
    pid_after = drained.succeed("systemctl show -p MainPID --value wgmesh-relayd.service").strip()
    drained.succeed("systemctl is-active wgmesh-relayd.service")
    assert pid_before not in ("", "0") and pid_before == pid_after, (
        f"{drained_name} was restarted by draining ({pid_before} -> {pid_after})"
    )
  '';
}
