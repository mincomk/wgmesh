# The wgmesh Rust workspace, built as one package.
#
# `cargo build` on the workspace root produces all three binaries -- wgmesh,
# wgmesh-relayd and wgmeshd -- and the install hook copies every executable it
# finds, so this single package is what the NixOS modules exec and what
# `packages.<system>.{wgmesh,wgmesh-relayd,wgmeshd}` are derived from.
{
  lib,
  rustPlatform,
  pkg-config,
  sqlite,
  version ? "0.1.0",
}:

rustPlatform.buildRustPackage {
  pname = "wgmesh";
  inherit version;

  # cleanSourceWith keeps the development tree out of the store: version
  # control metadata, editor backups and any local target/ directory.
  src = lib.cleanSourceWith {
    src = ../..;
    filter =
      path: type:
      lib.cleanSourceFilter path type && baseNameOf (toString path) != "target";
  };

  # The lock file is the single source of truth for dependency versions.
  # importCargoLock verifies every crate against the checksums recorded in it,
  # so there is no vendor hash to maintain by hand.
  cargoLock.lockFile = ../../Cargo.lock;

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [ sqlite ];

  # sqlx is compiled without a live database: the queries come from the
  # checked-in `.sqlx` offline cache, which `cargo sqlx prepare` regenerates.
  # CI builds with the same setting.
  env.SQLX_OFFLINE = "true";

  # The test suite needs loopback sockets and runs in CI and through the
  # `checks` outputs; the package build stays a build.
  doCheck = false;

  # Fail loudly if the workspace ever stops producing one of the three
  # binaries the NixOS modules exec.
  postInstall = ''
    for bin in wgmesh wgmesh-relayd wgmeshd; do
      if [ ! -x "$out/bin/$bin" ]; then
        echo "error: $out/bin/$bin is missing from the workspace build" >&2
        exit 1
      fi
    done
  '';

  meta = {
    description = "Self-hosted WireGuard mesh with NAT traversal";
    homepage = "https://github.com/mincomk/wgmesh";
    mainProgram = "wgmesh";
    platforms = lib.platforms.linux;
  };
}
