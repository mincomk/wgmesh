// Drives netlink futures from the synchronous port methods.

use std::future::Future;
use std::io;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

/// The bridge between the synchronous ports and the asynchronous netlink
/// crates.
///
/// The port traits are synchronous on purpose — everything except the HTTP API
/// is local I/O — while `rtnetlink` and `nl-wireguard` are asynchronous. This
/// type is the one place the two meet.
///
/// Inside a multi-threaded tokio runtime the future is driven on the runtime
/// that is already there, on a blocking worker thread, so a peer change asked
/// for from an async use case does not stall a reactor. Outside a runtime it
/// owns a single-threaded runtime of its own, built on first use.
#[derive(Debug, Default)]
pub struct NetlinkRuntime {
    owned: OnceLock<Runtime>,
}

impl NetlinkRuntime {
    /// A bridge that has not built its own runtime yet.
    pub const fn new() -> Self {
        Self {
            owned: OnceLock::new(),
        }
    }

    /// Drive `future` to completion and hand back its output.
    ///
    /// # Errors
    ///
    /// Fails when the caller is inside a current-thread tokio runtime, where
    /// blocking is impossible: the netlink call would deadlock rather than make
    /// progress, so the attempt is refused instead. An agent runs on a
    /// multi-threaded runtime and never reaches this.
    pub fn block_on<F: Future>(&self, future: F) -> io::Result<F::Output> {
        match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                Ok(tokio::task::block_in_place(|| handle.block_on(future)))
            }
            Ok(_) => Err(io::Error::other(
                "a current-thread tokio runtime can not block on netlink; \
                 run the agent on a multi-threaded runtime",
            )),
            Err(_) => Ok(self.runtime()?.block_on(future)),
        }
    }

    fn runtime(&self) -> io::Result<&Runtime> {
        if let Some(runtime) = self.owned.get() {
            return Ok(runtime);
        }
        let runtime = Builder::new_current_thread().enable_all().build()?;
        // A lost race only means another caller built an equivalent runtime
        // first; either one drives the same netlink socket.
        let _ = self.owned.set(runtime);
        self.owned
            .get()
            .ok_or_else(|| io::Error::other("netlink runtime vanished"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_future_runs_without_an_ambient_runtime() {
        let bridge = NetlinkRuntime::new();
        let output = bridge
            .block_on(async { 40 + 2 })
            .expect("the bridge built its own runtime");
        assert_eq!(output, 42);
    }

    #[test]
    fn the_owned_runtime_is_built_once() {
        let bridge = NetlinkRuntime::new();
        let first = bridge.block_on(async { 1 }).expect("first call");
        let second = bridge.block_on(async { 2 }).expect("second call");
        assert_eq!((first, second), (1, 2));
        assert!(bridge.owned.get().is_some());
    }

    #[test]
    fn a_multi_threaded_runtime_can_be_blocked_on() {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("a runtime");
        let bridge = NetlinkRuntime::new();
        let output = runtime.block_on(async { bridge.block_on(async { 7 }) });
        assert_eq!(output.expect("the ambient runtime is used"), 7);
    }
}
