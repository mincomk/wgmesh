// lab-coordinator: the coordinator process the conformance lab drives.
//
// Control plane only -- it binds a TCP listener and nothing else. The
// conformance suite checks that structurally, by reading this process's own
// /proc entry while a pair is relaying through a relay it assigned.

fn main() {
    wgmesh_conformance::coordinator::run();
}
