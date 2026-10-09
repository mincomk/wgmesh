{
  description = "wgmesh - a self-hosted WireGuard mesh with NAT traversal";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs, ... }:
    let
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = f: lib.genAttrs systems (system: f system);

      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };

      version = "0.1.0";

      # The repository as it is checked in, without build artifacts or VCS
      # metadata. Used for the xtask build and for the dependency check.
      source = lib.cleanSourceWith {
        src = self;
        filter =
          path: type:
          lib.cleanSourceFilter path type && baseNameOf (toString path) != "target";
      };
    in
    {
      overlays.default = final: prev: {
        wgmesh = final.callPackage ./nix/packages/wgmesh.nix { inherit version; };
      };

      nixosModules = rec {
        agent = ./nix/modules/agent.nix;
        relay = ./nix/modules/relay.nix;
        coordinator = ./nix/modules/coordinator.nix;
        default = {
          imports = [
            agent
            relay
            coordinator
          ];
        };
      };

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;

          wgmesh = pkgs.wgmesh;

          # The workspace build installs all three binaries. These wrappers give
          # each binary a package of its own, so `nix build .#wgmesh-relayd`
          # produces exactly the relay.
          mkBin =
            name:
            pkgs.runCommand "${name}-${version}" {
              meta = {
                description = "wgmesh ${name}";
                homepage = "https://github.com/mincomk/wgmesh";
                mainProgram = name;
                platforms = lib.platforms.linux;
              };
            } ''
              mkdir -p $out/bin
              ln -s ${wgmesh}/bin/${name} $out/bin/${name}
            '';

          # The repository checks live in the xtask crate; `checks.deps` needs
          # them as a derivation, so they are built (and exposed) here.
          xtask = pkgs.rustPlatform.buildRustPackage {
            pname = "wgmesh-xtask";
            inherit version;
            src = source;
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "xtask";
            doCheck = false;
          };
        in
        {
          inherit wgmesh xtask;

          wgmesh-relayd = mkBin "wgmesh-relayd";
          wgmeshd = mkBin "wgmeshd";

          default = wgmesh;

          # Runs `xtask check-deps` over the source: the dependency rules the
          # workspace promises are mechanically enforced, not documented.
          #
          # It has to run inside a Rust build environment. The xtask shells out
          # to `cargo metadata`, and a bare runCommand has neither cargo nor the
          # vendored registry that `cargoLock` sets up -- and a sandbox has no
          # network to fetch them from. So the check rides along with the build
          # of the tool it runs.
          xtask-deps = pkgs.rustPlatform.buildRustPackage {
            pname = "wgmesh-check-deps";
            inherit version;
            src = source;
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "xtask";
            doCheck = false;
            postBuild = ''
              check=$(find "$NIX_BUILD_TOP" -maxdepth 6 -type f -name xtask -perm -u+x 2>/dev/null | head -n1)
              if [ -z "$check" ]; then
                echo "error: could not find the built xtask binary" >&2
                exit 1
              fi
              "$check" check-deps
            '';
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          # `pkgs.nixosTest` was removed from nixpkgs (it is a throwing alias
          # that points at `testers.nixosTest`), so the checks go through
          # `testers`. It is the same function: a test module evaluated against
          # this nixpkgs, which is what a check outside nixpkgs wants.
          deps = self.packages.${system}.xtask-deps;
          e2e = pkgs.testers.nixosTest (import ./nix/tests/e2e.nix { inherit self; });
          relay-unit = pkgs.testers.nixosTest (import ./nix/tests/relay.nix { inherit self; });
          forwarding = pkgs.testers.nixosTest (import ./nix/tests/forwarding.nix { inherit self; });
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer
              pkg-config
              sqlite
              jq
            ];
          };
        }
      );
    };
}
