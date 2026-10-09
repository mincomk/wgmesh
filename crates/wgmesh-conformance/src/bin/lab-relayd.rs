// lab-relayd: one relay process.
//
// The relay is pull-based: it opens its UDP slots, then polls the coordinator
// with a heartbeat carrying its slots, the source addresses it has observed and
// its counters, and applies the directive it gets back. The coordinator
// therefore never has to reach the relay.

fn main() {
    wgmesh_conformance::relay::run();
}
